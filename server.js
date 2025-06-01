// server.js
// Backend CryptoMoz Invest Platform (Versão Consolidada e Corrigida)

// --- Dependências ---
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

// --- Constantes e Configurações Globais ---
const app = express();
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1d';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_NAME = process.env.ADMIN_NAME || 'Admin Default';
const ADMIN_SECURITY_QUESTION = process.env.ADMIN_SECURITY_QUESTION;
const ADMIN_SECURITY_ANSWER_RAW = process.env.ADMIN_SECURITY_ANSWER_RAW;

const DEFAULT_REGISTRATION_BONUS = parseFloat(process.env.DEFAULT_REGISTRATION_BONUS) || 0;
const DEFAULT_REFERRAL_PLAN_BONUS_PERCENT = parseFloat(process.env.DEFAULT_REFERRAL_PLAN_BONUS_PERCENT) || 0.0;
const DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT = parseFloat(process.env.DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT) || 0.0;
const DEFAULT_MIN_WITHDRAWAL = parseFloat(process.env.DEFAULT_MIN_WITHDRAWAL) || 50;
const DEFAULT_MAX_WITHDRAWAL = parseFloat(process.env.DEFAULT_MAX_WITHDRAWAL) || 100000;
const DEFAULT_WITHDRAWAL_FEE_PERCENT = parseFloat(process.env.DEFAULT_WITHDRAWAL_FEE_PERCENT) || 0.01;

// Timezone settings for profit collection
const TIMEZONE_OFFSET_HOURS = parseInt(process.env.TIMEZONE_OFFSET_HOURS) || 2; // Maputo GMT+2
const PROFIT_COLLECTION_START_HOUR = parseInt(process.env.PROFIT_COLLECTION_START_HOUR) || 8; // 8 AM


if (!MONGO_URI || !JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD || !ADMIN_SECURITY_QUESTION || !ADMIN_SECURITY_ANSWER_RAW) {
    console.error("FATAL ERROR: Variáveis de ambiente críticas não definidas. Verifique seu arquivo .env");
    process.exit(1);
}

// --- Middlewares Globais ---
app.use(express.json());
app.use(cors())

// -----------------------------------------------------------------------------
// --- MODELOS DO MONGOOSE (SCHEMAS) ---
// -----------------------------------------------------------------------------

const UserSchema = new mongoose.Schema({
    name: { type: String, required: [true, "O nome é obrigatório."], trim: true, minlength: 3 },
    email: { type: String, required: [true, "O email é obrigatório."], unique: true, trim: true, lowercase: true, match: [/\S+@\S+\.\S+/, 'Formato de email inválido.'] },
    password: { type: String, required: [true, "A senha é obrigatória."], minlength: [6, "A senha deve ter no mínimo 6 caracteres."] },
    securityQuestion: { type: String, required: [true, "A pergunta de segurança é obrigatória."] },
    securityAnswer: { type: String, required: [true, "A resposta de segurança é obrigatória."] },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    balance: { type: Number, default: 0, min: 0, validate: { validator: Number.isFinite, message: '{VALUE} não é um número finito para saldo.' } },
    referralCode: { type: String, unique: true, sparse: true, trim: true, uppercase: true },
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    isEligibleForRegistrationBonus: { type: Boolean, default: true },
    status: { type: String, enum: ['active', 'pending_verification', 'suspended', 'banned'], default: 'active'},
    lastLoginAt: { type: Date },
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

UserSchema.pre('save', async function(next) {
    this.updatedAt = Date.now();
    if (this.isModified('password') || (this.isNew && this.password)) {
        try {
            const salt = await bcrypt.genSalt(12);
            this.password = await bcrypt.hash(this.password, salt);
        } catch (error) { return next(error); }
    }
    if (this.isModified('securityAnswer') || (this.isNew && this.securityAnswer)) {
         try {
            const salt = await bcrypt.genSalt(12);
            this.securityAnswer = await bcrypt.hash(this.securityAnswer, salt);
        } catch (error) { return next(error); }
    }
    if (this.isNew && !this.referralCode) {
        let uniqueCode = false; let attempts = 0; const maxAttempts = 10;
        while (!uniqueCode && attempts < maxAttempts) {
            const potentialCode = crypto.randomBytes(4).toString('hex').toUpperCase();
            const UserModel = mongoose.model('User');
            const existingUser = await UserModel.findOne({ referralCode: potentialCode });
            if (!existingUser) { this.referralCode = potentialCode; uniqueCode = true; }
            attempts++;
        }
        if (!uniqueCode) { this.referralCode = `${crypto.randomBytes(3).toString('hex').toUpperCase()}${Date.now().toString().slice(-4)}`; }
    }
    next();
});
UserSchema.methods.comparePassword = async function(candidatePassword) { return bcrypt.compare(candidatePassword, this.password); };
UserSchema.methods.compareSecurityAnswer = async function(candidateAnswer) { return bcrypt.compare(candidateAnswer, this.securityAnswer); };
UserSchema.methods.createPasswordResetToken = function() {
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpires = Date.now() + 15 * 60 * 1000;
    return resetToken;
};
const User = mongoose.model('User', UserSchema);

const SystemSettingsSchema = new mongoose.Schema({
    singletonId: { type: String, default: 'main_settings', unique: true, required: true },
    registrationBonusAmount: { type: Number, default: DEFAULT_REGISTRATION_BONUS, min: 0 },
    referralPlanPurchaseBonusPercentage: { type: Number, default: DEFAULT_REFERRAL_PLAN_BONUS_PERCENT, min: 0, max: 1 },
    referralDailyProfitBonusPercentage: { type: Number, default: DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT, min: 0, max: 1 },
    minWithdrawalAmount: { type: Number, default: DEFAULT_MIN_WITHDRAWAL, min: 0 },
    maxWithdrawalAmount: { type: Number, default: DEFAULT_MAX_WITHDRAWAL, min: 0 },
    withdrawalFeePercentage: {type: Number, default: DEFAULT_WITHDRAWAL_FEE_PERCENT, min:0, max:1},
    defaultPlanDuration: { type: Number, default: 90, min: 1},
    isReferralSystemActive: { type: Boolean, default: true },
    isRegistrationBonusActive: { type: Boolean, default: true },
    lastUpdatedAt: { type: Date, default: Date.now }
});
SystemSettingsSchema.pre('save', function(next) { this.lastUpdatedAt = Date.now(); next(); });
const SystemSettings = mongoose.model('SystemSettings', SystemSettingsSchema);

const DepositMethodSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true, trim: true },
    instructions: { type: String, required: true, trim: true },
    accountDetailsSchema: { type: mongoose.Schema.Types.Mixed },
    paymentInfo: { type: mongoose.Schema.Types.Mixed, required: true },
    minAmount: { type: Number, default: 50, min: 1 },
    maxAmount: { type: Number, default: 100000, min: 1 },
    feePercentage: {type: Number, default: 0, min: 0, max: 1},
    feeFixed: {type: Number, default: 0, min: 0},
    iconClass: { type: String, default: 'bi-credit-card' },
    isActive: { type: Boolean, default: true, index: true },
    processingTimeText: { type: String, default: "Até 24 horas" },
    currency: { type: String, default: "MT", uppercase: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
DepositMethodSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
const DepositMethod = mongoose.model('DepositMethod', DepositMethodSchema);

const DepositRequestSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    amount: { type: Number, required: [true, "O valor é obrigatório."], min: [1, "Valor mínimo de depósito é 1."] },
    currency: { type: String, default: "MT", uppercase: true },
    depositMethod: { type: mongoose.Schema.Types.ObjectId, ref: 'DepositMethod', required: true },
    userTransactionReference: { type: String, required: [true, "A referência da transação é obrigatória."], trim: true },
    userNotes: { type: String, trim: true, maxlength: 500 },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'cancelled_by_user'], default: 'pending', index: true },
    adminNotes: { type: String, trim: true, maxlength: 500 },
    rejectionReason: { type: String, trim: true, maxlength: 500 },
    requestedAt: { type: Date, default: Date.now },
    processedAt: { type: Date }
});
const DepositRequest = mongoose.model('DepositRequest', DepositRequestSchema);

const WithdrawalRequestSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    amount: { type: Number, required: [true, "O valor é obrigatório."], min: [1, "Valor mínimo de saque é 1."] },
    currency: { type: String, default: "MT", uppercase: true },
    withdrawalMethodType: { type: String, required: true },
    withdrawalAccountDetails: { type: mongoose.Schema.Types.Mixed, required: true },
    feeCharged: { type: Number, default: 0 },
    netAmount: {type: Number },
    status: { type: String, enum: ['pending', 'approved', 'processing', 'completed', 'rejected', 'failed', 'cancelled_by_user'], default: 'pending', index: true },
    adminNotes: { type: String, trim: true, maxlength: 500 },
    rejectionReason: {type: String, trim: true, maxlength: 500},
    transactionIdFromProvider: {type: String, trim: true},
    requestedAt: { type: Date, default: Date.now },
    processedAt: { type: Date },
    completedAt: { type: Date }
});
WithdrawalRequestSchema.pre('save', function(next) {
    if (this.isModified('amount') || this.isModified('feeCharged')) {
        this.netAmount = this.amount - this.feeCharged;
    }
    next();
});
const WithdrawalRequest = mongoose.model('WithdrawalRequest', WithdrawalRequestSchema);

const TransactionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { 
        type: String, 
        enum: [
            'deposit_approved', 'withdrawal_processed', 'plan_purchase', 'profit_collection', 
            'referral_bonus_plan', 'referral_bonus_profit', 'registration_bonus', 
            'admin_credit', 'admin_debit', 'withdrawal_fee', 'other_fee'
        ], 
        required: true 
    },
    amount: { type: Number, required: true },
    currency: { type: String, default: 'MT', uppercase: true },
    description: { type: String, trim: true, required: true, maxlength: 255 },
    status: { type: String, enum: ['pending', 'completed', 'failed', 'reversed'], default: 'completed' },
    balanceBefore: { type: Number },
    balanceAfter: { type: Number },
    relatedDepositRequest: { type: mongoose.Schema.Types.ObjectId, ref: 'DepositRequest', default: null },
    relatedWithdrawalRequest: { type: mongoose.Schema.Types.ObjectId, ref: 'WithdrawalRequest', default: null },
    relatedInvestment: { type: mongoose.Schema.Types.ObjectId, ref: 'UserInvestment', default: null },
    relatedUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    transactionDate: { type: Date, default: Date.now, index: true }
});
const Transaction = mongoose.model('Transaction', TransactionSchema);

const NotificationSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    title: { type: String, required: true, trim: true, maxlength: 100 },
    message: { type: String, required: true, trim: true, maxlength: 500 },
    type: { type: String, enum: ['info', 'success', 'warning', 'error', 'profit', 'investment', 'deposit', 'withdrawal', 'referral'], default: 'info' },
    isRead: { type: Boolean, default: false, index: true },
    link: { type: String, default: null, trim: true },
    iconClass: { type: String, default: 'bi-info-circle'},
    createdAt: { type: Date, default: Date.now, index: true }
});
const Notification = mongoose.model('Notification', NotificationSchema);

const PlanSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, unique: true },
    price_mt: { type: Number, required: true, min: 1 },
    daily_profit_mt: { type: Number, required: true, min: 0.01 },
    duration_days: { type: Number, required: true, min: 1, default: 90 },
    hashrate_mhs: { type: Number, required: true, min: 0 },
    description: { type: String, trim: true, maxlength: 500, default: '' },
    icon_bs_class: { type: String, default: 'bi-gem' },
    isActive: { type: Boolean, default: true },
    features: [String],
    maxInvestmentsPerUser: { type: Number, default: 1 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
PlanSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
const Plan = mongoose.model('Plan', PlanSchema);

const UserInvestmentSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
    planSnapshot: { 
        name: {type: String, required: true}, price_mt: {type: Number, required: true},
        daily_profit_mt: {type: Number, required: true}, duration_days: {type: Number, required: true}
    },
    startDate: { type: Date, default: Date.now, index: true },
    endDate: { type: Date, required: true },
    isActive: { type: Boolean, default: true, index: true },
    totalProfitCollected: { type: Number, default: 0, min: 0 },
    uncollectedProfit: { type: Number, default: 0, min: 0 },
    lastProfitCalculationTime: { type: Date, default: Date.now },
    nextCollectionAvailableAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});
UserInvestmentSchema.pre('save', function(next) {
    if (this.isNew) {
        this.endDate = new Date(this.startDate.getTime() + this.planSnapshot.duration_days * 24 * 60 * 60 * 1000);
        let firstCollection = new Date(this.startDate);
        firstCollection.setUTCDate(firstCollection.getUTCDate() + 1);
        firstCollection.setUTCHours(PROFIT_COLLECTION_START_HOUR - TIMEZONE_OFFSET_HOURS, 0, 0, 0);
        this.nextCollectionAvailableAt = firstCollection;
        this.lastProfitCalculationTime = this.startDate;
    }
    next();
});
const UserInvestment = mongoose.model('UserInvestment', UserInvestmentSchema);

const BlogPostSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true, unique:true },
    slug: { type: String, required: true, unique: true, lowercase: true, trim: true },
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    snippet: { type: String, trim: true, maxlength: 300 },
    tags: [{ type: String, trim: true, lowercase: true }],
    isPublished: {type: Boolean, default: false, index: true},
    coverImageUrl: { type: String, trim: true },
    views: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now, index: true },
    updatedAt: { type: Date, default: Date.now }
});
BlogPostSchema.pre('save', function(next) { this.updatedAt = Date.now(); if(!this.slug){this.slug = this.title.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '');} if(!this.snippet && this.content){this.snippet = this.content.substring(0,250) + (this.content.length > 250 ? '...' : '');} next(); });
const BlogPost = mongoose.model('BlogPost', BlogPostSchema);

const PromotionSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true, trim: true },
    imageUrl: { type: String, trim: true, default: '' },
    linkUrl: { type: String, trim: true, default: '' },
    isActive: { type: Boolean, default: true, index: true },
    startDate: { type: Date, default: Date.now },
    endDate: { type: Date, default: null },
    countdownTargetDate: { type: Date, default: null },
    type: {type: String, enum: ['banner', 'popup', 'general'], default: 'general'},
    priority: {type: Number, default: 0},
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
PromotionSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
const Promotion = mongoose.model('Promotion', PromotionSchema);

// -----------------------------------------------------------------------------
// --- FUNÇÕES AUXILIARES E MIDDLEWARES ---
// -----------------------------------------------------------------------------
const protectRoute = (req, res, next) => {
    const authHeader = req.header('Authorization');
    let token;
    if (authHeader && authHeader.startsWith('Bearer ')) { token = authHeader.substring(7); }
    if (!token) { return res.status(401).json({ message: 'Acesso negado. Token não fornecido.' }); }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user; next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') return res.status(401).json({ message: 'Token expirado.' });
        if (err.name === 'JsonWebTokenError') return res.status(401).json({ message: 'Token inválido.' });
        return res.status(500).json({ message: 'Erro ao verificar token.' });
    }
};

const adminOnly = async (req, res, next) => {
    try {
        if (req.user && req.user.id) {
            const userFromDb = await User.findById(req.user.id).select('role status');
            if (userFromDb && userFromDb.role === 'admin' && userFromDb.status === 'active') { next(); }
            else { res.status(403).json({ message: 'Acesso negado. Apenas administradores.' }); }
        } else { res.status(401).json({ message: 'Não autorizado.' }); }
    } catch(error) { res.status(500).json({ message: "Erro ao verificar permissões."}); }
};

async function getOrInitializeSystemSettings() {
    try {
        let settings = await SystemSettings.findOne({ singletonId: 'main_settings' });
        if (!settings) {
            settings = new SystemSettings({
                registrationBonusAmount: DEFAULT_REGISTRATION_BONUS,
                referralPlanPurchaseBonusPercentage: DEFAULT_REFERRAL_PLAN_BONUS_PERCENT,
                referralDailyProfitBonusPercentage: DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT,
                minWithdrawalAmount: DEFAULT_MIN_WITHDRAWAL,
                maxWithdrawalAmount: DEFAULT_MAX_WITHDRAWAL,
                withdrawalFeePercentage: DEFAULT_WITHDRAWAL_FEE_PERCENT,
                defaultPlanDuration: parseInt(process.env.DEFAULT_PLAN_DURATION) || 90,
                isReferralSystemActive: process.env.IS_REFERRAL_SYSTEM_ACTIVE !== 'false',
                isRegistrationBonusActive: process.env.IS_REGISTRATION_BONUS_ACTIVE !== 'false'
            });
            await settings.save(); console.log('Configurações do sistema inicializadas.');
        }
        return settings;
    } catch (error) { console.error("Erro settings:", error.message); throw new Error("Falha config sistema."); }
}

async function createInitialAdmin() {
    try {
        if (!ADMIN_EMAIL || !ADMIN_PASSWORD) { console.warn("Admin default não definido."); return; }
        const adminExists = await User.findOne({ email: ADMIN_EMAIL });
        if (!adminExists) {
            const adminUser = new User({
                name: ADMIN_NAME, email: ADMIN_EMAIL, password: ADMIN_PASSWORD,
                securityQuestion: ADMIN_SECURITY_QUESTION || "Pergunta Padrão?", securityAnswer: ADMIN_SECURITY_ANSWER_RAW || "RespostaPadrão",
                role: 'admin', isEligibleForRegistrationBonus: false, status: 'active'
            });
            await adminUser.save(); console.log('Admin inicial criado!');
        }
    } catch (error) { console.error('Erro admin inicial:', error.message); }
}

async function createTransactionEntry(userId, type, amount, description, status = 'completed', balanceBefore, balanceAfter, relatedDocs = {}) {
    try {
        await Transaction.create({ user: userId, type, amount, description, status, balanceBefore, balanceAfter, ...relatedDocs });
    } catch (error) { console.error(`Erro transação [${type}] user ${userId}:`, error.message); }
}

async function createUserNotification(userId, title, message, type = 'info', link = null, iconClass = null) {
    try {
        const notificationData = { user: userId, title, message, type, link };
        if(iconClass) notificationData.iconClass = iconClass;
        else {
            const defaultIcons = {'success':'bi-check-circle-fill', 'error':'bi-x-octagon-fill', 'warning':'bi-exclamation-triangle-fill', 'profit':'bi-graph-up-arrow', 'investment':'bi-piggy-bank-fill', 'deposit':'bi-box-arrow-in-down', 'withdrawal':'bi-box-arrow-up-right', 'referral':'bi-people-fill'};
            notificationData.iconClass = defaultIcons[type] || 'bi-info-circle-fill';
        }
        await Notification.create(notificationData);
    } catch (error) { console.error(`Erro notificação ${userId}:`, error.message); }
}

async function updateUncollectedProfits(userId) {
    const now = new Date();
    const userInvestments = await UserInvestment.find({ user: userId, isActive: true });
    let totalNewlyAccrued = 0;

    for (const investment of userInvestments) {
        if (now < investment.startDate || now >= investment.endDate) {
            if (now >= investment.endDate && investment.isActive) {
                investment.isActive = false; await investment.save();
            }
            continue;
        }
        let calculationReferenceTime = new Date(investment.lastProfitCalculationTime);
        let startOfLastCalcDay = new Date(calculationReferenceTime.getFullYear(), calculationReferenceTime.getMonth(), calculationReferenceTime.getDate());
        let startOfCurrentDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        let daysPassedSinceLastCalc = 0;
        if (startOfCurrentDay > startOfLastCalcDay) {
            daysPassedSinceLastCalc = Math.floor((startOfCurrentDay.getTime() - startOfLastCalcDay.getTime()) / (1000 * 60 * 60 * 24));
        }
        if (daysPassedSinceLastCalc > 0) {
            const investmentEndDate = new Date(investment.endDate);
            const daysLeftInInvestment = Math.max(0, Math.floor((investmentEndDate.getTime() - startOfLastCalcDay.getTime()) / (1000 * 60 * 60 * 24)));
            const daysToCredit = Math.min(daysPassedSinceLastCalc, daysLeftInInvestment);
            if (daysToCredit > 0) {
                const profitToAdd = daysToCredit * investment.planSnapshot.daily_profit_mt;
                investment.uncollectedProfit = (investment.uncollectedProfit || 0) + profitToAdd;
                investment.lastProfitCalculationTime = new Date(startOfLastCalcDay.getTime() + daysToCredit * 24 * 60 * 60 * 1000);
                totalNewlyAccrued += profitToAdd;
                await investment.save();
            }
        }
         if (now >= investment.endDate && investment.isActive) {
            investment.isActive = false; await investment.save();
            await createUserNotification(investment.user, "Plano Concluído", `Plano "${investment.planSnapshot.name}" concluído.`, "info", "/investments/my-history");
        }
    }
    if (totalNewlyAccrued > 0) {
        await createUserNotification(userId, "Lucros Calculados", `${totalNewlyAccrued.toFixed(2)} MT em lucros calculados.`, "profit", "/investments/my-active");
    }
    return { message: "Lucros não coletados atualizados." };
}

// -----------------------------------------------------------------------------
// --- ROTAS DA API ---
// -----------------------------------------------------------------------------
app.get('/api', (req, res) => res.json({ message: 'API CryptoMoz Invest Funcionando!' }));

// --- Rotas de Autenticação (/api/auth) ---
const authRouter = express.Router();
// (Rotas de /api/auth/register, /login, /recover/* como definidas anteriormente)
authRouter.post('/register', async (req, res) => { try { const { name, email, password, confirmPassword, securityQuestion, securityAnswer, referralCodeProvided } = req.body; if (!name || !email || !password || !confirmPassword || !securityQuestion || !securityAnswer) return res.status(400).json({m:'Campos obrigatórios.'}); if(password!==confirmPassword)return res.status(400).json({m:'Senhas não coincidem.'});if(password.length<6)return res.status(400).json({m:'Senha < 6 chars.'}); const el=email.toLowerCase();let eu=await User.findOne({email:el});if(eu)return res.status(400).json({m:'Email já existe.'});let rbi=null;let rr=null;if(referralCodeProvided&&referralCodeProvided.trim()!==''){rr=await User.findOne({referralCode:referralCodeProvided.trim().toUpperCase()});if(rr)rbi=rr._id;else console.warn(`Código indicação "${referralCodeProvided}" inválido.`);}const ss=await getOrInitializeSystemSettings();let ib=0;let rba=0;let uiefb=true;if(ss.isRegistrationBonusActive&&ss.registrationBonusAmount>0&&uiefb){ib+=ss.registrationBonusAmount;rba=ss.registrationBonusAmount;uiefb=false;}const nu=new User({name,email:el,password,securityQuestion,securityAnswer,referredBy:rbi,balance:ib,isEligibleForRegistrationBonus:uiefb});await nu.save();if(rba>0){await createTransactionEntry(nu._id,'registration_bonus',rba,'Bônus Cadastro','completed',0,nu.balance);await createUserNotification(nu._id,'Bem-vindo!',`Bônus de ${rba.toFixed(2)} MT recebido!`,'success','/wallet');}if(rr){await createUserNotification(rr._id,'Nova Indicação!',`${nu.name} usou seu código!`,'info','/referrals');}res.status(201).json({m:'Registrado!',userId:nu._id});}catch(e){console.error("Erro registro:",e);if(e.name==='ValidationError')return res.status(400).json({m:"Dados inválidos.",e:Object.values(e.errors).map(v=>v.message)});res.status(500).json({m:'Erro servidor.'})}});
authRouter.post('/login', async (req, res) => { try{const{email,password}=req.body;if(!email||!password)return res.status(400).json({m:'Email/senha obrigatórios.'});const u=await User.findOne({email:email.toLowerCase()});if(!u)return res.status(401).json({m:'Credenciais inválidas.'});if(u.status!=='active')return res.status(403).json({m:`Conta ${u.status}.`});const MAL=5;const LT=15*60*1000;if(u.lockUntil&&u.lockUntil>Date.now())return res.status(403).json({m:`Conta bloqueada. Tente em ${Math.ceil((u.lockUntil-Date.now())/60000)} min.`});const iM=await u.comparePassword(password);if(!iM){u.failedLoginAttempts+=1;if(u.failedLoginAttempts>=MAL){u.lockUntil=Date.now()+LT;await createUserNotification(u._id,"Conta Bloqueada","Login falhou muitas vezes.",'error');}await u.save();return res.status(401).json({m:'Credenciais inválidas.'});}u.failedLoginAttempts=0;u.lockUntil=undefined;u.lastLoginAt=Date.now();await u.save();const p={user:{id:u.id,name:u.name,email:u.email,role:u.role,status:u.status}};const t=jwt.sign(p,JWT_SECRET,{expiresIn:JWT_EXPIRES_IN});res.json({m:"Login OK!",token:t,user:p.user});}catch(e){console.error("Erro login:",e);res.status(500).json({m:'Erro servidor.'})}});
authRouter.post('/recover/request-question', async(req,res)=>{try{const{email}=req.body;if(!email)return res.status(400).json({m:"Email obrigatório."});const u=await User.findOne({email:email.toLowerCase()}).select('securityQuestion email');if(!u)return res.status(404).json({m:"Email não encontrado."});res.json({email:u.email,securityQuestion:u.securityQuestion});}catch(e){res.status(500).json({m:"Erro."})}});
authRouter.post('/recover/verify-answer', async(req,res)=>{try{const{email,securityAnswer}=req.body;if(!email||!securityAnswer)return res.status(400).json({m:"Email/resposta obrigatórios."});const u=await User.findOne({email:email.toLowerCase()});if(!u)return res.status(404).json({m:"Email não encontrado."});const iAM=await u.compareSecurityAnswer(securityAnswer);if(!iAM)return res.status(401).json({m:"Resposta incorreta."});const rT=u.createPasswordResetToken();await u.save({validateBeforeSave:false});console.log(`Recovery Token(dev):${rT}`);res.json({m:"Verificado. Token gerado (15min).",rTfT:rT});}catch(e){res.status(500).json({m:"Erro."})}});
authRouter.post('/recover/reset-password', async(req,res)=>{try{const{token,newPassword,confirmNewPassword}=req.body;if(!token||!newPassword||!confirmNewPassword)return res.status(400).json({m:"Token/senhas obrigatórios."});if(newPassword.length<6)return res.status(400).json({m:"Senha < 6 chars."});if(newPassword!==confirmNewPassword)return res.status(400).json({m:"Senhas não coincidem."});const hT=crypto.createHash('sha256').update(token).digest('hex');const u=await User.findOne({passwordResetToken:hT,passwordResetExpires:{$gt:Date.now()}});if(!u)return res.status(400).json({m:"Token inválido/expirado."});u.password=newPassword;u.passwordResetToken=undefined;u.passwordResetExpires=undefined;u.failedLoginAttempts=0;u.lockUntil=undefined;await u.save();await createUserNotification(u._id,"Senha Redefinida","Senha redefinida.",'success');res.json({m:"Senha atualizada."});}catch(e){res.status(500).json({m:"Erro."})}});
app.use('/api/auth', authRouter);

// --- Rotas de Perfil do Usuário (/api/users) ---
const userRouter = express.Router();
userRouter.use(protectRoute);
userRouter.get('/profile', async(req,res)=>{try{const u=await User.findById(req.user.id).select('-password -securityQuestion -securityAnswer -passwordResetToken -passwordResetExpires -failedLoginAttempts -lockUntil -__v');if(!u)return res.status(404).json({m:"Usuário não encontrado."});res.json(u);}catch(e){res.status(500).json({m:"Erro perfil."})}});
userRouter.put('/profile', async(req,res)=>{try{const{name}=req.body;const uD={};if(name&&name.trim().length>=3)uD.name=name.trim();else if(name)return res.status(400).json({m:"Nome < 3 chars."});if(Object.keys(uD).length===0)return res.status(400).json({m:"Nada para atualizar."});const u=await User.findByIdAndUpdate(req.user.id,uD,{new:true,runValidators:true}).select('-password -securityQuestion -securityAnswer -__v');if(!u)return res.status(404).json({m:"Usuário não encontrado."});res.json({m:"Perfil atualizado.",user:u});}catch(e){if(e.name==='ValidationError')return res.status(400).json({m:"Dados inválidos.",e:Object.values(e.errors).map(v=>v.message)});res.status(500).json({m:"Erro atualizar."})}});
userRouter.put('/change-password', async(req,res)=>{try{const{currentPassword,newPassword,confirmNewPassword}=req.body;if(!currentPassword||!newPassword||!confirmNewPassword)return res.status(400).json({m:"Campos obrigatórios."});if(newPassword.length<6)return res.status(400).json({m:"Senha < 6 chars."});if(newPassword!==confirmNewPassword)return res.status(400).json({m:"Senhas não coincidem."});const u=await User.findById(req.user.id);if(!u)return res.status(404).json({m:"Usuário não encontrado."});const iM=await u.comparePassword(currentPassword);if(!iM)return res.status(401).json({m:"Senha atual incorreta."});if(await bcrypt.compare(newPassword,u.password))return res.status(400).json({m:"Nova senha igual à atual."});u.password=newPassword;await u.save();await createUserNotification(u._id,"Senha Alterada","Sua senha foi alterada.",'success');res.json({m:"Senha alterada."});}catch(e){res.status(500).json({m:"Erro alterar senha."})}});
userRouter.get('/referral-details', async(req,res)=>{try{const u=await User.findById(req.user.id).select('referralCode');if(!u)return res.status(404).json({m:"Usuário não encontrado."});const rC=await User.countDocuments({referredBy:req.user.id});const rBR=await Transaction.aggregate([{$match:{user:new mongoose.Types.ObjectId(req.user.id),type:{$in:['referral_bonus_plan','referral_bonus_profit']}}},{$group:{_id:null,total:{$sum:'$amount'}}}]);res.json({rC:u.referralCode,tRU:rC,tRBE:rBR.length>0?rBR[0].total.toFixed(2):"0.00"});}catch(e){res.status(500).json({m:"Erro detalhes indicação."})}});
userRouter.get('/transactions', async(req,res)=>{try{const p=parseInt(req.query.page)||1;const l=parseInt(req.query.limit)||15;const s=(p-1)*l;const tF=req.query.type;let q={user:req.user.id};if(tF)q.type=tF;const ts=await Transaction.find(q).sort({transactionDate:-1}).skip(s).limit(l);const tT=await Transaction.countDocuments(q);res.json({ts,cP:p,tP:Math.ceil(tT/l),tT});}catch(e){res.status(500).json({m:"Erro transações."})}});
userRouter.get('/notifications', async(req,res)=>{try{const p=parseInt(req.query.page)||1;const l=parseInt(req.query.limit)||10;const s=(p-1)*l;const n=await Notification.find({user:req.user.id}).sort({createdAt:-1}).skip(s).limit(l);const tN=await Notification.countDocuments({user:req.user.id});const uC=await Notification.countDocuments({user:req.user.id,isRead:false});res.json({n,cP:p,tP:Math.ceil(tN/l),tN,uC});}catch(e){res.status(500).json({m:"Erro notificações."})}});
userRouter.put('/notifications/:id/read', async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID inválido."});const n=await Notification.findOneAndUpdate({_id:req.params.id,user:req.user.id},{isRead:true},{new:true});if(!n)return res.status(404).json({m:"Notificação não encontrada."});res.json({m:"Lida.",notification:n});}catch(e){res.status(500).json({m:"Erro."})}});
userRouter.put('/notifications/read-all', async(req,res)=>{try{await Notification.updateMany({user:req.user.id,isRead:false},{isRead:true});res.json({m:"Todas lidas."});}catch(e){res.status(500).json({m:"Erro."})}});
app.use('/api/users', userRouter);

// --- Rotas de Admin (/api/admin) ---
const adminRouter = express.Router();
adminRouter.use(protectRoute, adminOnly); 
// (Rotas de /api/admin/* como definidas anteriormente, incluindo settings, users, deposit-methods, etc.)
adminRouter.get('/settings',async(req,res)=>{try{const s=await getOrInitializeSystemSettings();res.json(s);}catch(e){res.status(500).json({m:"Erro settings."})}});
adminRouter.put('/settings',async(req,res)=>{try{const u=req.body;const s=await SystemSettings.findOne({singletonId:'main_settings'});if(!s)return res.status(404).json({m:"Config não encontrada."});Object.keys(u).forEach(k=>{if(s[k]!==undefined&&typeof s[k]==='number')s[k]=parseFloat(u[k]);else if(s[k]!==undefined&&typeof s[k]==='boolean')s[k]=(u[k]===true||u[k]==='true');else if(s[k]!==undefined)s[k]=u[k];});await s.save();res.json({m:"Config atualizada!",settings:s});}catch(e){res.status(500).json({m:"Erro atualizar."})}});
adminRouter.get('/users',async(req,res)=>{try{const p=parseInt(req.query.page)||1;const l=parseInt(req.query.limit)||15;const s=(p-1)*l;const{search,role,status,sortBy='createdAt',sortOrder='desc'}=req.query;let q={};if(search)q.$or=[{name:{$regex:search,$options:'i'}},{email:{$regex:search,$options:'i'}}];if(role)q.role=role;if(status)q.status=status;const o={};o[sortBy]=sortOrder==='asc'?1:-1;const us=await User.find(q).select('-password -securityAnswer').sort(o).skip(s).limit(l).populate('referredBy','name email');const tU=await User.countDocuments(q);res.json({us,cP:p,tP:Math.ceil(tU/l),tU});}catch(e){res.status(500).json({m:"Erro listar."})}});
adminRouter.get('/users/:id',async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const u=await User.findById(req.params.id).select('-password -securityAnswer').populate('referredBy','name email');if(!u)return res.status(404).json({m:"Não enc."});const inv=await UserInvestment.find({user:u._id}).populate('plan','name price_mt').sort({startDate:-1});const tr=await Transaction.find({user:u._id}).sort({transactionDate:-1}).limit(20);const wR=await WithdrawalRequest.find({user:u._id}).sort({requestedAt:-1}).limit(10);const dR=await DepositRequest.find({user:u._id}).sort({requestedAt:-1}).limit(10);res.json({user:u,investments:inv,transactions:tr,withdrawalRequests:wR,depositRequests:dR});}catch(e){res.status(500).json({m:"Erro buscar."})}});
adminRouter.put('/users/:id/update-details',async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const{name,email,role,status,balanceAdjustment,adjustmentReason}=req.body;const u=await User.findById(req.params.id);if(!u)return res.status(404).json({m:"Não enc."});let eC=false;if(name&&name.trim()!=='')u.name=name.trim();if(email&&email.toLowerCase()!==u.email){const eE=await User.findOne({email:email.toLowerCase()});if(eE&&eE._id.toString()!==u._id.toString())return res.status(400).json({m:"Email em uso."});u.email=email.toLowerCase();eC=true;}if(role)u.role=role;if(status){if(u.status!==status&&status==='active'){u.failedLoginAttempts=0;u.lockUntil=null;}u.status=status;}if(balanceAdjustment!==undefined&&typeof balanceAdjustment==='number'&&balanceAdjustment!==0){if(!adjustmentReason)return res.status(400).json({m:"Razão obrigatória."});const oB=u.balance;const nB=u.balance+balanceAdjustment;if(nB<0)return res.status(400).json({m:"Saldo negativo."});u.balance=nB;await createTransactionEntry(u._id,balanceAdjustment>0?'admin_credit':'admin_debit',balanceAdjustment,`Admin: ${adjustmentReason}`,'completed',oB,nB);await createUserNotification(u._id,"Saldo Ajustado",`Saldo ajustado em ${balanceAdjustment.toFixed(2)} MT. Razão: ${adjustmentReason}.`,'info');}await u.save();const uTR=u.toObject();delete uTR.password;delete uTR.securityAnswer;res.json({m:"Usuário atualizado.",user:uTR,emailChanged:eC});}catch(e){res.status(500).json({m:"Erro."})}});
adminRouter.put('/users/:id/status',async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const{status,reason}=req.body;if(!status||!['active','suspended','banned'].includes(status))return res.status(400).json({m:"Status inválido."});const u=await User.findById(req.params.id);if(!u)return res.status(404).json({m:"Não enc."});if(u.role==='admin'&&status!=='active'){const aA=await User.countDocuments({role:'admin',status:'active'});if(aA<=1&&u.id===req.user.id)return res.status(400).json({m:"Não pode desativar único admin."});}u.status=status;if(status==='active'){u.failedLoginAttempts=0;u.lockUntil=null;}await u.save();await createUserNotification(u._id,"Status da Conta",`Status: ${status}. ${reason?'Razão:'+reason:''}`,status==='active'?'success':'warning');const uTR=u.toObject();delete uTR.password;delete uTR.securityAnswer;res.json({m:`Status: ${status}.`,user:uTR});}catch(e){res.status(500).json({m:"Erro."})}});
adminRouter.post('/deposit-methods',async(req,res)=>{try{const{name,instructions,paymentInfo}=req.body;if(!name||!instructions||!paymentInfo)return res.status(400).json({m:"Campos obrigatórios."});const m=new DepositMethod(req.body);await m.save();res.status(201).json({m:"Adicionado.",method:m});}catch(e){if(e.code===11000)return res.status(400).json({m:"Nome já existe."});res.status(500).json({m:"Erro."})}});
adminRouter.get('/deposit-methods',async(req,res)=>{try{const m=await DepositMethod.find().sort({name:1});res.json(m);}catch(e){res.status(500).json({m:"Erro."})}});
adminRouter.put('/deposit-methods/:id',async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const m=await DepositMethod.findByIdAndUpdate(req.params.id,req.body,{new:true,runValidators:true});if(!m)return res.status(404).json({m:"Não encontrado."});res.json({m:"Atualizado.",method:m});}catch(e){if(e.code===11000)return res.status(400).json({m:"Nome já existe."});res.status(500).json({m:"Erro."})}});
adminRouter.delete('/deposit-methods/:id',async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const m=await DepositMethod.findByIdAndDelete(req.params.id);if(!m)return res.status(404).json({m:"Não encontrado."});res.json({m:"Removido."});}catch(e){res.status(500).json({m:"Erro."})}});
adminRouter.get('/deposit-requests',async(req,res)=>{try{const{status,page=1,limit=10}=req.query;const q=status?{status}:{};const r=await DepositRequest.find(q).populate('user','name email').populate('depositMethod','name').sort({requestedAt:-1}).limit(limit*1).skip((page-1)*limit);const c=await DepositRequest.countDocuments(q);res.json({requests:r,totalPages:Math.ceil(c/limit),currentPage:parseInt(page)}); /* Corrigido para requests e currentPage */ }catch(e){res.status(500).json({m:"Erro."})}});
adminRouter.put('/deposit-requests/:id/process',async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const{status,adminNotes}=req.body;if(!['approved','rejected'].includes(status))return res.status(400).json({m:"Status inválido."});const r=await DepositRequest.findById(req.params.id).populate('depositMethod', 'name');if(!r||r.status!=='pending')return res.status(404).json({m:"Solicitação não pendente."});r.status=status;r.adminNotes=adminNotes||'';r.processedAt=Date.now();const u=await User.findById(r.user);if(!u)return res.status(404).json({m:"Usuário não encontrado."});if(status==='approved'){const bB=u.balance;u.balance+=r.amount;await u.save();await createTransactionEntry(u._id,'deposit_approved',r.amount,`Depósito Aprovado via ${r.depositMethod?.name || 'N/A'}. Ref:${r.userTransactionReference}`,'completed',bB,u.balance,{relatedDepositRequest:r._id});await createUserNotification(u._id,"Depósito Aprovado",`Depósito de ${r.amount.toFixed(2)} MT aprovado.`,'success','/transactions');}else{r.rejectionReason=adminNotes||'Não especificado.'; await createUserNotification(u._id,"Depósito Rejeitado",`Depósito de ${r.amount.toFixed(2)} MT rejeitado. ${r.rejectionReason}`,'error');}await r.save();res.json({m:`Solicitação ${status}.`,request:r});}catch(e){console.error("Erro proc depo:",e);res.status(500).json({m:"Erro."})}});
adminRouter.get('/withdrawal-requests',async(req,res)=>{try{const{status,page=1,limit=10}=req.query;const q=status?{status}:{};const r=await WithdrawalRequest.find(q).populate('user','name email balance').sort({requestedAt:-1}).limit(limit*1).skip((page-1)*limit);const c=await WithdrawalRequest.countDocuments(q);res.json({requests:r,totalPages:Math.ceil(c/limit),currentPage:parseInt(page)}); /* Corrigido para requests e currentPage */ }catch(e){res.status(500).json({m:"Erro."})}});
adminRouter.put('/withdrawal-requests/:id/process',async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const{status,adminNotes,transactionIdFromProvider}=req.body;if(!['approved','processing','completed','rejected'].includes(status))return res.status(400).json({m:"Status inválido."});const r=await WithdrawalRequest.findById(req.params.id);if(!r)return res.status(404).json({m:"Solicitação não encontrada."});const u=await User.findById(r.user);if(!u)return res.status(404).json({m:"Usuário não encontrado."});const oS=r.status;r.status=status;r.adminNotes=adminNotes||r.adminNotes;if(transactionIdFromProvider)r.transactionIdFromProvider=transactionIdFromProvider;r.processedAt=Date.now();let nM='';let nT='info';if(oS==='pending'&&status==='approved'){nM=`Saque de ${r.amount.toFixed(2)} MT aprovado, aguardando processamento.`;nT='success';}else if(status==='processing'&&oS!=='processing'){nM=`Saque de ${r.amount.toFixed(2)} MT está sendo processado.`;nT='info';}else if(status==='completed'&&oS!=='completed'){const sS=await getOrInitializeSystemSettings();const fee=r.amount*sS.withdrawalFeePercentage;const netAmountToWithdraw=r.amount-fee;if(u.balance<r.amount){r.status='failed';r.rejectionReason='Saldo insuficiente no processamento final.';await r.save();await createUserNotification(u._id,"Falha no Saque",`Saque de ${r.amount.toFixed(2)} MT falhou por saldo.`,'error');return res.status(400).json({m:"Saldo insuficiente."});}const bB=u.balance;u.balance-=r.amount;await u.save();r.completedAt=Date.now();r.feeCharged=fee;r.netAmount=netAmountToWithdraw;await createTransactionEntry(u._id,'withdrawal_processed',-r.amount,`Saque ${r.amount.toFixed(2)} MT (${r.withdrawalMethodType})`,'completed',bB,u.balance,{relatedWithdrawalRequest:r._id});if(fee>0)await createTransactionEntry(u._id,'withdrawal_fee',-fee,`Taxa de saque para ${r.amount.toFixed(2)} MT`,'completed',bB-r.amount,u.balance);nM=`Saque de ${r.amount.toFixed(2)} MT concluído.`;nT='success';}else if(status==='rejected'){r.rejectionReason=adminNotes||'Não especificado';nM=`Saque de ${r.amount.toFixed(2)} MT rejeitado. ${r.rejectionReason}`;nT='error';}await r.save();if(nM)await createUserNotification(u._id,"Status do Saque",nM,nT,'/transactions');res.json({m:`Status do saque: ${status}.`,request:r});}catch(e){console.error("Erro proc saque:",e);res.status(500).json({m:"Erro."})}});
adminRouter.get('/investments', async (req, res) => { try { const p=parseInt(req.query.page)||1;const l=parseInt(req.query.limit)||15;const s=(p-1)*l;const{userId,planId,isActive,sort='-startDate'}=req.query;let q={};if(userId)q.user=userId;if(planId)q.plan=planId;if(isActive!==undefined)q.isActive=isActive==='true';const inv=await UserInvestment.find(q).populate('user','name email').populate('plan','name').sort(sort).skip(s).limit(l);const tI=await UserInvestment.countDocuments(q);res.json({investments:inv,cP:p,tP:Math.ceil(tI/l),tI}); } catch (e) { res.status(500).json({m:"Erro."})}});
adminRouter.get('/investments/:id', async (req, res) => { try { if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const inv=await UserInvestment.findById(req.params.id).populate('user','name email balance').populate('plan');if(!inv)return res.status(404).json({m:"Não enc."});res.json(inv);}catch(e){res.status(500).json({m:"Erro."})}});
adminRouter.put('/investments/:id/status', async (req, res) => { try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const{isActive,adminNotes}=req.body;if(typeof isActive!=='boolean')return res.status(400).json({m:"Status obrigatório."});const inv=await UserInvestment.findById(req.params.id).populate('planSnapshot');if(!inv)return res.status(404).json({m:"Não enc."});inv.isActive=isActive;await inv.save();await createUserNotification(inv.user,`Status Investimento Alterado`,`Plano "${inv.planSnapshot.name}" ${isActive?'Ativo':'Inativo'}. ${adminNotes||''}`,isActive?'info':'warning');res.json({m:"Status atualizado.",investment:inv});}catch(e){res.status(500).json({m:"Erro."})}});
adminRouter.get('/stats/overview', async(req,res)=>{try{const tU=await User.countDocuments();const tAP=await Plan.countDocuments({isActive:true});const tAI=await UserInvestment.countDocuments({isActive:true});const tDR=await Transaction.aggregate([{$match:{type:'deposit_approved'}},{$group:{_id:null,total:{$sum:'$amount'}}}]);const tWR=await WithdrawalRequest.aggregate([{$match:{status:'completed'}},{$group:{_id:null,total:{$sum:'$amount'}}}]);const tPCR=await Transaction.aggregate([{$match:{type:'profit_collection'}},{$group:{_id:null,total:{$sum:'$amount'}}}]);res.json({tU,tAP,tAI,tD:tDR[0]?.total||0,tWS:tWR[0]?.total||0,tPPTU:tPCR[0]?.total||0,pW:await WithdrawalRequest.countDocuments({status:'pending'}),pD:await DepositRequest.countDocuments({status:'pending'})});}catch(e){res.status(500).json({m:"Erro stats."})}});
adminRouter.get('/stats/user-growth', async(req,res)=>{try{const d=parseInt(req.query.days)||30;const t=new Date();t.setUTCHours(0,0,0,0);const dL=new Date(t);dL.setDate(t.getDate()-d);const uG=await User.aggregate([{$match:{createdAt:{$gte:dL}}},{$group:{_id:{$dateToString:{format:"%Y-%m-%d",date:"$createdAt",timezone:"Africa/Maputo"}},count:{$sum:1}}},{$sort:{_id:1}}]);res.json(uG);}catch(e){res.status(500).json({m:"Erro stats user."})}});
app.use('/api/admin', adminRouter);

// --- Rotas Públicas para Planos e Métodos de Depósito ---
const publicPlanRouter = express.Router();
publicPlanRouter.get('/',async(req,res)=>{try{const p=await Plan.find({isActive:true}).sort({price_mt:1});res.json(p);}catch(e){res.status(500).json({m:"Erro."})}});
publicPlanRouter.get('/:id',async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const p=await Plan.findById(req.params.id);if(!p||!p.isActive)return res.status(404).json({m:"Não enc."});res.json(p);}catch(e){res.status(500).json({m:"Erro."})}});
app.use('/api/plans', publicPlanRouter);

const publicDepositMethodRouter = express.Router();
publicDepositMethodRouter.get('/', async(req,res)=>{try{const m=await DepositMethod.find({isActive:true}).select('-createdAt -updatedAt -__v -accountDetailsSchema');res.json(m);}catch(e){res.status(500).json({m:"Erro."})}});
app.use('/api/deposit-methods', publicDepositMethodRouter); // Não protegido, para usuários verem antes de solicitar

// --- Rotas para Usuário Submeter Solicitação de Depósito e Saque ---
const depositUserRouter = express.Router();
depositUserRouter.post('/request', async(req,res)=>{try{const{amount,depositMethodId,userTransactionReference}=req.body;if(!amount||!depositMethodId||!userTransactionReference)return res.status(400).json({m:"Campos obrigatórios."});if(!mongoose.Types.ObjectId.isValid(depositMethodId))return res.status(400).json({m:"ID método inválido."});const meth=await DepositMethod.findById(depositMethodId);if(!meth||!meth.isActive)return res.status(404).json({m:"Método não ativo."});if(parseFloat(amount)<meth.minAmount||parseFloat(amount)>meth.maxAmount)return res.status(400).json({m:`Valor entre ${meth.minAmount} e ${meth.maxAmount} MT.`});const nR=new DepositRequest({user:req.user.id,amount:parseFloat(amount),depositMethod:depositMethodId,userTransactionReference});await nR.save();await createUserNotification(req.user.id,"Solicitação de Depósito Recebida",`Sua solicitação de ${nR.amount.toFixed(2)} MT está em processamento.`,'info');res.status(201).json({m:"Solicitação de depósito recebida. Aguarde o processamento.",r:nR});}catch(e){res.status(500).json({m:"Erro."})}});
app.use('/api/deposits', protectRoute, depositUserRouter);

const withdrawalUserRouter = express.Router();
withdrawalUserRouter.post('/request', async(req,res)=>{try{const{amount,withdrawalMethodType,withdrawalAccountDetails}=req.body;if(!amount||!withdrawalMethodType||!withdrawalAccountDetails)return res.status(400).json({m:"Campos obrigatórios."});const pA=parseFloat(amount);if(isNaN(pA)||pA<=0)return res.status(400).json({m:"Valor inválido."});const sS=await getOrInitializeSystemSettings();if(pA<sS.minWithdrawalAmount||pA>sS.maxWithdrawalAmount)return res.status(400).json({m:`Valor entre ${sS.minWithdrawalAmount} e ${sS.maxWithdrawalAmount} MT.`});const u=await User.findById(req.user.id);if(!u)return res.status(404).json({m:"Usuário não encontrado."});const fee=pA*sS.withdrawalFeePercentage;const totalDebit=pA+fee;if(u.balance<totalDebit)return res.status(400).json({m:"Saldo insuficiente (incluindo taxa)."});const pW=await WithdrawalRequest.findOne({user:req.user.id,status:'pending'});if(pW)return res.status(400).json({m:"Já possui saque pendente."});const nR=new WithdrawalRequest({user:req.user.id,amount:pA,withdrawalMethodType,withdrawalAccountDetails,feeCharged:fee});await nR.save();await createUserNotification(req.user.id,"Solicitação de Saque Recebida",`Saque de ${nR.amount.toFixed(2)} MT em processamento.`,'info');res.status(201).json({m:"Solicitação de saque recebida. Estamos processando.",r:nR});}catch(e){res.status(500).json({m:"Erro."})}});
app.use('/api/withdrawals', protectRoute, withdrawalUserRouter);


// --- ROTAS DE INVESTIMENTOS DO USUÁRIO (/api/investments) CORRIGIDO ---
const investmentRouter = express.Router(); // Definição do Router

// POST /api/investments (Usuário: Investir em um plano)
investmentRouter.post('/', async (req, res) => { try { const { planId } = req.body; if (!planId || !mongoose.Types.ObjectId.isValid(planId)) return res.status(400).json({m:"ID plano inválido."}); const plan = await Plan.findOne({ _id: planId, isActive: true }); if (!plan) return res.status(404).json({m:"Plano não encontrado/inativo."}); const user = await User.findById(req.user.id); if (!user) return res.status(404).json({m:"Usuário não encontrado."}); if (user.balance < plan.price_mt) return res.status(400).json({m:"Saldo insuficiente."}); const bB=user.balance; user.balance -= plan.price_mt; const nI = new UserInvestment({ user:user._id, plan:plan._id, planSnapshot:{name:plan.name,price_mt:plan.price_mt,daily_profit_mt:plan.daily_profit_mt,duration_days:plan.duration_days}}); await nI.save(); await createTransactionEntry(user._id,'plan_purchase',-plan.price_mt, `Compra: ${plan.name}`,'completed',bB,user.balance,{relatedInvestment:nI._id}); if(user.referredBy){const r=await User.findById(user.referredBy);const sS=await getOrInitializeSystemSettings();if(r&&sS.isReferralSystemActive&&sS.referralPlanPurchaseBonusPercentage>0){const bA=plan.price_mt*sS.referralPlanPurchaseBonusPercentage;if(bA>0){const rBB=r.balance;r.balance+=bA;await r.save();await createTransactionEntry(r._id,'referral_bonus_plan',bA,`Bônus indicação (${user.name})`,'completed',rBB,r.balance,{relatedUser:user._id});await createUserNotification(r._id,'Bônus de Indicação!',`Recebeu ${bA.toFixed(2)} MT por ${user.name} adquirir ${plan.name}.`,'success','/referrals');}}} await user.save(); await createUserNotification(user._id,'Investimento Realizado!',`Investiu em ${plan.name}.`,'success','/investments/my-history'); res.status(201).json({m:"Investimento realizado!",investment:nI});}catch(e){console.error("Erro investimento:",e);res.status(500).json({m:"Erro."})}});
investmentRouter.get('/my-active', async (req, res) => { try { await updateUncollectedProfits(req.user.id); const aI = await UserInvestment.findOne({ user: req.user.id, isActive: true }).populate('plan', 'name icon_bs_class hashrate_mhs'); if(!aI) return res.json(null); res.json(aI); } catch (e) { res.status(500).json({m:"Erro."})}});
investmentRouter.post('/collect-profit', async (req, res) => { try { const uId = req.user.id; await updateUncollectedProfits(uId); const inv = await UserInvestment.findOne({user:uId,isActive:true}); if(!inv) return res.status(404).json({m:"Investimento ativo não encontrado."}); const now=new Date(); if(inv.nextCollectionAvailableAt&&now<inv.nextCollectionAvailableAt){const tLMs=inv.nextCollectionAvailableAt.getTime()-now.getTime();const hL=Math.floor(tLMs/(1000*60*60));const mL=Math.floor((tLMs%(1000*60*60))/(1000*60));return res.status(400).json({m:`Coleta disponível em ${hL}h ${mL}m.`});} if(inv.uncollectedProfit<=0)return res.status(400).json({m:"Nenhum lucro para coletar."}); const u=await User.findById(uId); if(!u)return res.status(404).json({m:"Usuário não encontrado."}); const cA=parseFloat(inv.uncollectedProfit.toFixed(2)); const bBC=u.balance; u.balance+=cA; inv.totalProfitCollected+=cA; inv.uncollectedProfit=0; inv.lastCollectedAt=now; let nC=new Date(now.toLocaleString("en-US",{timeZone:"Africa/Maputo"})); nC.setDate(nC.getDate()+1); nC.setHours(PROFIT_COLLECTION_START_HOUR,0,0,0); inv.nextCollectionAvailableAt=new Date(Date.UTC(nC.getFullYear(),nC.getMonth(),nC.getDate(),nC.getHours(),0,0,0)-(TIMEZONE_OFFSET_HOURS*60*60*1000)); await createTransactionEntry(u._id,'profit_collection',cA,`Coleta lucro: ${inv.planSnapshot.name}`,'completed',bBC,u.balance,{relatedInvestment:inv._id}); if(u.referredBy){const r=await User.findById(u.referredBy);const sS=await getOrInitializeSystemSettings();if(r&&sS.isReferralSystemActive&&sS.referralDailyProfitBonusPercentage>0){const dPB=parseFloat((cA*sS.referralDailyProfitBonusPercentage).toFixed(2));if(dPB>0){const rBB=r.balance;r.balance+=dPB;await r.save();await createTransactionEntry(r._id,'referral_bonus_profit',dPB,`Bônus coleta ${u.name}`,'completed',rBB,r.balance,{relatedUser:u._id});await createUserNotification(r._id,'Bônus Indicação!',`Recebeu ${dPB.toFixed(2)} MT por coleta de ${u.name}.`,'success','/referrals');}}} await u.save(); await inv.save(); await createUserNotification(u._id,'Lucros Coletados!',`${cA.toFixed(2)} MT coletados. Saldo: ${u.balance.toFixed(2)} MT.`,'success','/wallet'); res.json({m:`${cA.toFixed(2)} MT coletados!`,newBalance:u.balance.toFixed(2)}); } catch(e){console.error("Erro coleta:",e);res.status(500).json({m:"Erro."})}});
investmentRouter.get('/my-history', async (req, res) => { try { const p=parseInt(req.query.page)||1;const l=parseInt(req.query.limit)||10;const s=(p-1)*l;const q={user:req.user.id};const invs=await UserInvestment.find(q).populate('plan','name icon_bs_class').sort({startDate:-1}).skip(s).limit(l);const tI=await UserInvestment.countDocuments(q);res.json({investments:invs,cP:p,tP:Math.ceil(tI/l),tI});}catch(e){res.status(500).json({m:"Erro."})}});

app.use('/api/investments', protectRoute, investmentRouter); // Aplicar protectRoute para todas as rotas de investimento


// --- ROTAS DE BLOG (/api/blog) ---
const blogRouter = express.Router();
// (Implementações completas como na Parte 2 do pensamento anterior)
blogRouter.post('/',protectRoute,adminOnly,async(req,res)=>{try{const{title,content}=req.body;if(!title||!content)return res.status(400).json({m:"Título/Conteúdo obrigatórios."});let pS=req.body.slug;if(!pS)pS=title.toLowerCase().replace(/\s+/g,'-').replace(/[^\w-]+/g,'');const eS=await BlogPost.findOne({slug:pS});if(eS)return res.status(400).json({m:"Slug já existe."});const p=new BlogPost({...req.body,slug:pS,author:req.user.id});await p.save();res.status(201).json({m:"Post criado!",post:p});}catch(e){if(e.code===11000)return res.status(400).json({m:"Título/Slug já existe."});if(e.name==='ValidationError')return res.status(400).json({m:"Validação.",e:Object.values(e.errors).map(v=>v.message)});res.status(500).json({m:"Erro."})}});
blogRouter.get('/',async(req,res)=>{try{const p=parseInt(req.query.page)||1;const l=parseInt(req.query.limit)||10;const s=(p-1)*l;const t=req.query.tag;const sQ=req.query.search;let q={isPublished:true};if(t)q.tags=t.trim().toLowerCase();if(sQ)q.title={$regex:sQ,$options:'i'};const ps=await BlogPost.find(q).populate('author','name').sort({createdAt:-1}).skip(s).limit(l).select('title slug snippet tags createdAt coverImageUrl author views');const tP=await BlogPost.countDocuments(q);res.json({posts:ps,cP:p,tP:Math.ceil(tP/l),tP});}catch(e){res.status(500).json({m:"Erro."})}});
blogRouter.get('/all',protectRoute,adminOnly,async(req,res)=>{try{const p=parseInt(req.query.page)||1;const l=parseInt(req.query.limit)||20;const s=(p-1)*l;const{isPublished,search}=req.query;let q={};if(isPublished!==undefined)q.isPublished=(isPublished==='true');if(search)q.title={$regex:search,$options:'i'};const ps=await BlogPost.find(q).populate('author','name').sort({createdAt:-1}).skip(s).limit(l);const tP=await BlogPost.countDocuments(q);res.json({posts:ps,cP:p,tP:Math.ceil(tP/l),tP});}catch(e){res.status(500).json({m:"Erro."})}});
blogRouter.get('/slug/:slug',async(req,res)=>{try{const p=await BlogPost.findOneAndUpdate({slug:req.params.slug.toLowerCase(),isPublished:true},{$inc:{views:1}},{new:true}).populate('author','name');if(!p)return res.status(404).json({m:"Post não encontrado."});res.json(p);}catch(e){res.status(500).json({m:"Erro."})}});
blogRouter.get('/id/:id',protectRoute,adminOnly,async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const p=await BlogPost.findById(req.params.id).populate('author','name');if(!p)return res.status(404).json({m:"Não enc."});res.json(p);}catch(e){res.status(500).json({m:"Erro."})}});
blogRouter.put('/:id',protectRoute,adminOnly,async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const uD={...req.body};if(uD.slug){const nS=uD.slug.toLowerCase().replace(/\s+/g,'-').replace(/[^\w-]+/g,'');const ePWS=await BlogPost.findOne({slug:nS,_id:{$ne:req.params.id}});if(ePWS)return res.status(400).json({m:"Slug já existe."});uD.slug=nS;}if(uD.title&&!uD.slug){uD.slug=uD.title.toLowerCase().replace(/\s+/g,'-').replace(/[^\w-]+/g,'');}if(uD.content&&uD.snippet===undefined){uD.snippet=uD.content.substring(0,250)+(uD.content.length>250?'...':'');}uD.updatedAt=Date.now();const p=await BlogPost.findByIdAndUpdate(req.params.id,{$set:uD},{new:true,runValidators:true});if(!p)return res.status(404).json({m:"Não enc."});res.json({m:"Post atualizado!",post:p});}catch(e){if(e.code===11000)return res.status(400).json({m:"Título/Slug já existe."});if(e.name==='ValidationError')return res.status(400).json({m:"Validação.",e:Object.values(e.errors).map(v=>v.message)});res.status(500).json({m:"Erro."})}});
blogRouter.delete('/:id',protectRoute,adminOnly,async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const p=await BlogPost.findByIdAndDelete(req.params.id);if(!p)return res.status(404).json({m:"Não enc."});res.json({m:"Post deletado."});}catch(e){res.status(500).json({m:"Erro."})}});
app.use('/api/blog', blogRouter);

// --- ROTAS DE PROMOÇÕES (/api/promotions) ---
const promotionRouter = express.Router();
// (Implementações completas como na Parte 2 do pensamento anterior)
promotionRouter.post('/',protectRoute,adminOnly,async(req,res)=>{try{const{title,description}=req.body;if(!title||!description)return res.status(400).json({m:"Título/Descrição obrigatórios."});const nP=new Promotion({...req.body,isActive:req.body.isActive===true,startDate:req.body.startDate?new Date(req.body.startDate):Date.now(),endDate:req.body.endDate?new Date(req.body.endDate):null,countdownTargetDate:req.body.countdownTargetDate?new Date(req.body.countdownTargetDate):null});await nP.save();res.status(201).json({m:"Promoção criada!",promotion:nP});}catch(e){if(e.name==='ValidationError')return res.status(400).json({m:"Validação.",e:Object.values(e.errors).map(v=>v.message)});res.status(500).json({m:"Erro."})}});
promotionRouter.get('/active',async(req,res)=>{try{const n=new Date();const p=await Promotion.find({isActive:true,$or:[{startDate:{$lte:n}},{startDate:null}],$or:[{endDate:{$gte:n}},{endDate:null}]}).sort({priority:-1,createdAt:-1});res.json(p);}catch(e){res.status(500).json({m:"Erro."})}});
promotionRouter.get('/all',protectRoute,adminOnly,async(req,res)=>{try{const p=parseInt(req.query.page)||1;const l=parseInt(req.query.limit)||10;const s=(p-1)*l;const iAF=req.query.isActive;let q={};if(iAF!==undefined)q.isActive=(iAF==='true');const ps=await Promotion.find(q).sort({createdAt:-1}).skip(s).limit(l);const tP=await Promotion.countDocuments(q);res.json({promotions:ps,cP:p,tP:Math.ceil(tP/l),tP});}catch(e){res.status(500).json({m:"Erro."})}});
promotionRouter.get('/:id',protectRoute,adminOnly,async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const p=await Promotion.findById(req.params.id);if(!p)return res.status(404).json({m:"Não enc."});res.json(p);}catch(e){res.status(500).json({m:"Erro."})}});
promotionRouter.put('/:id',protectRoute,adminOnly,async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const uD={...req.body};if(uD.isActive!==undefined)uD.isActive=(uD.isActive===true||uD.isActive==='true');if(uD.startDate)uD.startDate=new Date(uD.startDate);if(uD.endDate)uD.endDate=new Date(uD.endDate);else if(uD.endDate==='')uD.endDate=null;if(uD.countdownTargetDate)uD.countdownTargetDate=new Date(uD.countdownTargetDate);else if(uD.countdownTargetDate==='')uD.countdownTargetDate=null;const uP=await Promotion.findByIdAndUpdate(req.params.id,{$set:uD},{new:true,runValidators:true});if(!uP)return res.status(404).json({m:"Não enc."});res.json({m:"Promoção atualizada!",promotion:uP});}catch(e){if(e.name==='ValidationError')return res.status(400).json({m:"Validação.",e:Object.values(e.errors).map(v=>v.message)});res.status(500).json({m:"Erro."})}});
promotionRouter.delete('/:id',protectRoute,adminOnly,async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID Inv."});const p=await Promotion.findByIdAndDelete(req.params.id);if(!p)return res.status(404).json({m:"Não enc."});res.json({m:"Promoção deletada."});}catch(e){res.status(500).json({m:"Erro."})}});
app.use('/api/promotions', promotionRouter);


// -----------------------------------------------------------------------------
// --- FUNÇÃO PRINCIPAL PARA INICIAR O SERVIDOR E CHAMADA FINAL ---
// -----------------------------------------------------------------------------
async function startServer() {
    if (!MONGO_URI) { console.error("FATAL: MONGO_URI não definida."); process.exit(1); }
    if (!JWT_SECRET) { console.error("FATAL: JWT_SECRET não definido."); process.exit(1); }
    try {
        await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        console.log('MongoDB Conectado!');
        await getOrInitializeSystemSettings(); 
        await createInitialAdmin(); 
        app.listen(PORT, () => {
            console.log(`Servidor Backend CryptoMoz rodando na Porta ${PORT}`);
            console.log('Todas as rotas e configurações carregadas. Backend pronto!');
        });
    } catch (error) { console.error('Falha Crítica ao Iniciar Servidor:', error.message); process.exit(1); }
}

if (require.main === module) { 
  startServer();
}

// module.exports = app; // Para testes