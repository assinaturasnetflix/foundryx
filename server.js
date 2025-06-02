// server.js
// Backend Foundry Invest Platform (Versão Consolidada e Corrigida pelo Usuário com Foco na Compra de Plano)

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
const ADMIN_NAME = process.env.ADMIN_NAME || 'Admin Foundry'; 
const ADMIN_SECURITY_QUESTION = process.env.ADMIN_SECURITY_QUESTION;
const ADMIN_SECURITY_ANSWER_RAW = process.env.ADMIN_SECURITY_ANSWER_RAW;

const DEFAULT_REGISTRATION_BONUS = parseFloat(process.env.DEFAULT_REGISTRATION_BONUS) || 0;
const DEFAULT_REFERRAL_PLAN_BONUS_PERCENT = parseFloat(process.env.DEFAULT_REFERRAL_PLAN_BONUS_PERCENT) || 0.0;
const DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT = parseFloat(process.env.DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT) || 0.0;
const DEFAULT_MIN_WITHDRAWAL = parseFloat(process.env.DEFAULT_MIN_WITHDRAWAL) || 100; 
const DEFAULT_MAX_WITHDRAWAL = parseFloat(process.env.DEFAULT_MAX_WITHDRAWAL) || 100000;
const DEFAULT_WITHDRAWAL_FEE_PERCENT = parseFloat(process.env.DEFAULT_WITHDRAWAL_FEE_PERCENT) || 0.01;

const TIMEZONE_OFFSET_HOURS = parseInt(process.env.TIMEZONE_OFFSET_HOURS) || 2; 
const PROFIT_COLLECTION_START_HOUR = parseInt(process.env.PROFIT_COLLECTION_START_HOUR) || 8;


if (!MONGO_URI || !JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD || !ADMIN_SECURITY_QUESTION || !ADMIN_SECURITY_ANSWER_RAW) {
    console.error("ERRO FATAL: Variáveis de ambiente críticas não definidas. Verifique seu arquivo .env");
    process.exit(1);
}

// --- Middlewares Globais ---
app.use(cors()); 
app.use(express.json()); 

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
    canWithdrawBonus: { type: Boolean, default: false }, // ATUALIZADO: Campo para controlar saque de bônus
    status: { type: String, enum: ['active', 'pending_verification', 'suspended', 'banned'], default: 'active'},
    lastLoginAt: { type: Date },
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },
    oneTimeLoginToken: { type: String, sparse: true }, // Mantido da sua última versão completa
    oneTimeLoginTokenExpires: { type: Date },     // Mantido da sua última versão completa
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

UserSchema.pre('save', async function(next) { 
    this.updatedAt = Date.now();
    if (this.isModified('password') || (this.isNew && this.password)) {
        try { const salt = await bcrypt.genSalt(12); this.password = await bcrypt.hash(this.password, salt); } catch (error) { return next(error); }
    }
    if (this.isModified('securityAnswer') || (this.isNew && this.securityAnswer)) {
         try { const salt = await bcrypt.genSalt(12); this.securityAnswer = await bcrypt.hash(this.securityAnswer, salt); } catch (error) { return next(error); }
    }
    if (this.isNew && !this.referralCode) {
        let uniqueCode = false; let attempts = 0; const maxAttempts = 10;
        while (!uniqueCode && attempts < maxAttempts) {
            const potentialCode = crypto.randomBytes(4).toString('hex').toUpperCase();
            const UserModel = mongoose.model('User'); 
            const existingUser = await UserModel.findOne({ referralCode: potentialCode });
            if (!existingUser) { this.referralCode = potentialCode; uniqueCode = true; } attempts++;
        }
        if (!uniqueCode) { this.referralCode = `${crypto.randomBytes(3).toString('hex').toUpperCase()}${Date.now().toString().slice(-4)}`; }
    }
    next();
});
UserSchema.methods.comparePassword = async function(candidatePassword) { return bcrypt.compare(candidatePassword, this.password); };
UserSchema.methods.compareSecurityAnswer = async function(candidateAnswer) { return bcrypt.compare(candidateAnswer, this.securityAnswer); };
UserSchema.methods.createPasswordResetToken = function() {
    const resetToken = crypto.randomBytes(20).toString('hex'); 
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpires = Date.now() + 15 * 60 * 1000; 
    return resetToken;
};
UserSchema.methods.createOneTimeLoginToken = function() { // Mantido da sua última versão completa
    const loginToken = crypto.randomBytes(32).toString('hex');
    this.oneTimeLoginToken = crypto.createHash('sha256').update(loginToken).digest('hex');
    this.oneTimeLoginTokenExpires = Date.now() + 15 * 60 * 1000; // 15 minutos
    return loginToken; 
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
    bonusWithdrawalRequiresPlan: { type: Boolean, default: true }, // ATUALIZADO: Configuração para saque de bônus
    lastUpdatedAt: { type: Date, default: Date.now }
});
SystemSettingsSchema.pre('save', function(next) { this.lastUpdatedAt = Date.now(); next(); });
const SystemSettings = mongoose.model('SystemSettings', SystemSettingsSchema);

const DepositMethodSchema = new mongoose.Schema({ /* ... como no seu código original ... */ 
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

const DepositRequestSchema = new mongoose.Schema({ /* ... como no seu código original ... */ 
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

const WithdrawalRequestSchema = new mongoose.Schema({ /* ... como no seu código original ... */ 
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
    if (this.isModified('amount') || this.isModified('feeCharged')) { this.netAmount = this.amount - this.feeCharged; } next();
});
const WithdrawalRequest = mongoose.model('WithdrawalRequest', WithdrawalRequestSchema);

const TransactionSchema = new mongoose.Schema({ /* ... como no seu código original, com admin_plan_assignment ... */ 
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { 
        type: String, 
        enum: [
            'deposit_approved', 'withdrawal_processed', 'plan_purchase', 'profit_collection', 
            'referral_bonus_plan', 'referral_bonus_profit', 'registration_bonus', 
            'admin_credit', 'admin_debit', 'withdrawal_fee', 'admin_plan_assignment',
            'other_fee'
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

const NotificationSchema = new mongoose.Schema({ /* ... como no seu código original ... */ 
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

const PlanSchema = new mongoose.Schema({ /* ... como no seu código original ... */ 
    name: { type: String, required: true, trim: true, unique: true },
    price_mt: { type: Number, required: true, min: 1 },
    daily_profit_mt: { type: Number, required: true, min: 0.01 },
    duration_days: { type: Number, required: true, min: 1, default: 90 },
    hashrate_mhs: { type: Number, required: true, min: 0 }, 
    description: { type: String, trim: true, maxlength: 500, default: '' },
    icon_bs_class: { type: String, default: 'bi-gem' }, 
    isActive: { type: Boolean, default: true, index: true },
    features: [String], 
    maxInvestmentsPerUser: { type: Number, default: 1, min: 0 }, 
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
    endDate: { type: Date, required: true }, // endDate é required
    isActive: { type: Boolean, default: true, index: true }, 
    totalProfitCollected: { type: Number, default: 0, min: 0 },
    uncollectedProfit: { type: Number, default: 0, min: 0 }, 
    lastProfitCalculationTime: { type: Date, default: Date.now }, 
    nextCollectionAvailableAt: { type: Date }, 
    lastCollectedAt: {type: Date },
    createdAt: { type: Date, default: Date.now }
});
// O HOOK pre('save') FOI MOVIDO PARA DENTRO DA ROTA DE CRIAÇÃO DE UserInvestment PARA GARANTIR QUE endDate SEJA DEFINIDO
const UserInvestment = mongoose.model('UserInvestment', UserInvestmentSchema);

const BlogPostSchema = new mongoose.Schema({ /* ... como no seu código original ... */ 
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

const PromotionSchema = new mongoose.Schema({ /* ... como no seu código original, mas confirmando 'blog' no enum ... */ 
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true, trim: true },
    imageUrl: { type: String, trim: true, default: '' },
    linkUrl: { type: String, trim: true, default: '' }, 
    isActive: { type: Boolean, default: true, index: true },
    startDate: { type: Date, default: Date.now },
    endDate: { type: Date, default: null }, 
    countdownTargetDate: { type: Date, default: null }, 
    type: {type: String, enum: ['banner', 'popup', 'general', 'blog'], default: 'general'}, // 'blog' confirmado
    priority: {type: Number, default: 0}, 
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
PromotionSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
const Promotion = mongoose.model('Promotion', PromotionSchema);

const CountdownSchema = new mongoose.Schema({ /* ... como definido anteriormente ... */ 
    title: { type: String, required: [true, "O título do contador é obrigatório."], trim: true },
    description: { type: String, trim: true },
    targetDate: { type: Date, required: [true, "A data alvo é obrigatória."] },
    isActive: { type: Boolean, default: true, index: true },
    actionLink: { type: String, trim: true, default: '' }, 
    displayLocation: { type: String, enum: ['dashboard_top', 'event_page', 'sidebar'], default: 'dashboard_top' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
CountdownSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
const Countdown = mongoose.model('Countdown', CountdownSchema);


// -----------------------------------------------------------------------------
// --- FUNÇÕES AUXILIARES E MIDDLEWARES ---
// -----------------------------------------------------------------------------
const protectRoute = (req, res, next) => { /* ... como no seu código original ... */ 
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
        console.error("[Foundry] Erro na verificação do token:", err);
        return res.status(500).json({ message: 'Erro ao verificar token.' });
    }
};

const adminOnly = async (req, res, next) => { /* ... como no seu código original ... */ 
    try {
        if (req.user && req.user.id) {
            const userFromDb = await User.findById(req.user.id).select('role status');
            if (userFromDb && userFromDb.role === 'admin' && userFromDb.status === 'active') { next(); }
            else { res.status(403).json({ message: 'Acesso negado. Apenas administradores.' }); }
        } else { res.status(401).json({ message: 'Não autorizado.' }); }
    } catch(error) { console.error("[Foundry] Erro na verificação de admin:", error); res.status(500).json({ message: "Erro ao verificar permissões de administrador."}); }
};

async function getOrInitializeSystemSettings() { /* ... como no seu código original, com bonusWithdrawalRequiresPlan ... */ 
    try {
        let settings = await SystemSettings.findOne({ singletonId: 'main_settings' });
        if (!settings) {
            console.log('[Foundry] Nenhuma configuração do sistema encontrada, inicializando com padrões...');
            settings = new SystemSettings({
                registrationBonusAmount: DEFAULT_REGISTRATION_BONUS,
                referralPlanPurchaseBonusPercentage: DEFAULT_REFERRAL_PLAN_BONUS_PERCENT,
                referralDailyProfitBonusPercentage: DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT,
                minWithdrawalAmount: DEFAULT_MIN_WITHDRAWAL,
                maxWithdrawalAmount: DEFAULT_MAX_WITHDRAWAL,
                withdrawalFeePercentage: DEFAULT_WITHDRAWAL_FEE_PERCENT,
                defaultPlanDuration: parseInt(process.env.DEFAULT_PLAN_DURATION) || 90,
                isReferralSystemActive: process.env.IS_REFERRAL_SYSTEM_ACTIVE !== 'false', 
                isRegistrationBonusActive: process.env.IS_REGISTRATION_BONUS_ACTIVE !== 'false',
                bonusWithdrawalRequiresPlan: true 
            });
            await settings.save();
            console.log('[Foundry] Configurações do sistema inicializadas com sucesso.');
        }
        return settings;
    } catch (error) { console.error("[Foundry] Erro ao obter/inicializar configurações:", error.message); throw new Error("Falha ao carregar as configurações do sistema."); }
}

async function createInitialAdmin() { /* ... como no seu código original, com nome Foundry e canWithdrawBonus ... */ 
    try {
        if (!ADMIN_EMAIL || !ADMIN_PASSWORD) { console.warn("[Foundry] Credenciais do admin padrão não definidas. Admin não será criado."); return; }
        const adminExists = await User.findOne({ email: ADMIN_EMAIL });
        if (!adminExists) {
            const adminUser = new User({
                name: ADMIN_NAME, email: ADMIN_EMAIL, password: ADMIN_PASSWORD, 
                securityQuestion: ADMIN_SECURITY_QUESTION || "Pergunta de Segurança Padrão?",
                securityAnswer: ADMIN_SECURITY_ANSWER_RAW || "RespostaPadrão123", 
                role: 'admin', isEligibleForRegistrationBonus: false, status: 'active',
                canWithdrawBonus: true 
            });
            await adminUser.save(); console.log('[Foundry] Usuário administrador inicial criado com sucesso!');
        }
    } catch (error) { console.error('[Foundry] Erro ao criar administrador inicial:', error.message); }
}

async function createTransactionEntry(userId, type, amount, description, status = 'completed', balanceBefore, balanceAfter, relatedDocs = {}) { /* ... como no seu código original ... */ 
    try { await Transaction.create({ user: userId, type, amount, description, status, balanceBefore, balanceAfter, ...relatedDocs });
    } catch (error) { console.error(`[Foundry] Erro ao criar transação [${type}] para usuário ${userId}:`, error.message); }
}

async function createUserNotification(userId, title, message, type = 'info', link = null, iconClass = null) { /* ... como no seu código original ... */ 
    try {
        const notificationData = { user: userId, title, message, type, link };
        if(iconClass) { notificationData.iconClass = iconClass; } 
        else {
            const defaultIcons = {'success':'bi-check-circle-fill', 'error':'bi-x-octagon-fill', 'warning':'bi-exclamation-triangle-fill', 'profit':'bi-graph-up-arrow', 'investment':'bi-piggy-bank-fill', 'deposit':'bi-box-arrow-in-down', 'withdrawal':'bi-box-arrow-up-right', 'referral':'bi-people-fill'};
            notificationData.iconClass = defaultIcons[type] || 'bi-info-circle-fill'; 
        }
        await Notification.create(notificationData);
    } catch (error) { console.error(`[Foundry] Erro ao criar notificação para usuário ${userId}:`, error.message); }
}

async function updateUncollectedProfits(userId) { /* ... como no seu código original ... */ 
    const now = new Date();
    const userInvestments = await UserInvestment.find({ user: userId, isActive: true });
    let totalNewlyAccruedProfit = 0;
    for (const investment of userInvestments) {
        if (now >= investment.endDate) { if (investment.isActive) { investment.isActive = false; await investment.save(); await createUserNotification(investment.user, "Plano Concluído", `Seu plano de investimento "${investment.planSnapshot.name}" foi concluído.`, "info", "/investments/my-history"); } continue; }
        if (now < investment.startDate) continue;
        let calculationReferenceTime = new Date(investment.lastProfitCalculationTime);
        let startOfLastCalcDayLocal = new Date(calculationReferenceTime); startOfLastCalcDayLocal.setHours(startOfLastCalcDayLocal.getHours() + TIMEZONE_OFFSET_HOURS); startOfLastCalcDayLocal.setHours(0,0,0,0); 
        let startOfCurrentDayLocal = new Date(now); startOfCurrentDayLocal.setHours(startOfCurrentDayLocal.getHours() + TIMEZONE_OFFSET_HOURS); startOfCurrentDayLocal.setHours(0,0,0,0); 
        let daysPassedSinceLastCalc = 0;
        if (startOfCurrentDayLocal > startOfLastCalcDayLocal) { daysPassedSinceLastCalc = Math.floor((startOfCurrentDayLocal.getTime() - startOfLastCalcDayLocal.getTime()) / (1000 * 60 * 60 * 24)); }
        if (daysPassedSinceLastCalc > 0) {
            const investmentEndDate = new Date(investment.endDate);
            const daysLeftInInvestment = Math.max(0, Math.floor((investmentEndDate.getTime() - startOfLastCalcDayLocal.getTime()) / (1000 * 60 * 60 * 24)));
            const daysToCredit = Math.min(daysPassedSinceLastCalc, daysLeftInInvestment);
            if (daysToCredit > 0) {
                const profitToAdd = daysToCredit * investment.planSnapshot.daily_profit_mt;
                investment.uncollectedProfit = (investment.uncollectedProfit || 0) + profitToAdd;
                let newLastCalcTimeLocal = new Date(startOfLastCalcDayLocal); newLastCalcTimeLocal.setDate(newLastCalcTimeLocal.getDate() + daysToCredit);
                investment.lastProfitCalculationTime = new Date(Date.UTC(newLastCalcTimeLocal.getFullYear(), newLastCalcTimeLocal.getMonth(), newLastCalcTimeLocal.getDate(),0 - TIMEZONE_OFFSET_HOURS,0,0,0));
                totalNewlyAccruedProfit += profitToAdd; await investment.save();
            }
        }
    }
    if (totalNewlyAccruedProfit > 0) { await createUserNotification(userId, "Lucros Diários Calculados", `Um total de ${totalNewlyAccruedProfit.toFixed(2)} MT em lucros diários foram calculados.`, "profit", "/investments/my-active"); }
    return { message: "Lucros não coletados atualizados." };
}


// -----------------------------------------------------------------------------
// --- ROTAS DA API ---
// -----------------------------------------------------------------------------
app.get('/api', (req, res) => res.json({ message: 'API Foundry Invest Funcionando!' }));

// --- Rotas de Autenticação (/api/auth) ---
const authRouter = express.Router();
authRouter.post('/register', async (req, res) => { /* ... como no seu código original ... */ 
    try {
        const { name, email, password, confirmPassword, securityQuestion, securityAnswer, referralCodeProvided } = req.body;
        if (!name || !email || !password || !confirmPassword || !securityQuestion || !securityAnswer) { return res.status(400).json({ m: 'Todos os campos marcados com * são obrigatórios.' }); }
        if (password !== confirmPassword) return res.status(400).json({ m: 'As senhas fornecidas não coincidem.' });
        if (password.length < 6) return res.status(400).json({ m: 'A senha deve ter no mínimo 6 caracteres.' });
        const normalizedEmail = email.toLowerCase();
        let existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) return res.status(400).json({ m: 'Este endereço de email já está em uso.' });
        let referredByUser = null;
        if (referralCodeProvided && referralCodeProvided.trim() !== '') {
            referredByUser = await User.findOne({ referralCode: referralCodeProvided.trim().toUpperCase() });
            if (!referredByUser) { console.warn(`[Foundry] Código de indicação "${referralCodeProvided}" fornecido mas não encontrado.`); }
        }
        const systemSettings = await getOrInitializeSystemSettings();
        let initialBalance = 0; let registrationBonusApplied = 0; let userIsEligibleForBonus = true;
        if (systemSettings.isRegistrationBonusActive && systemSettings.registrationBonusAmount > 0 && userIsEligibleForBonus) {
            initialBalance += systemSettings.registrationBonusAmount; registrationBonusApplied = systemSettings.registrationBonusAmount; userIsEligibleForBonus = false; 
        }
        const newUser = new User({ name, email: normalizedEmail, password, securityQuestion, securityAnswer, referredBy: referredByUser ? referredByUser._id : null, balance: initialBalance, isEligibleForRegistrationBonus: userIsEligibleForBonus });
        await newUser.save();
        if (registrationBonusApplied > 0) {
            await createTransactionEntry(newUser._id, 'registration_bonus', registrationBonusApplied, 'Bônus de Registro Foundry', 'completed', 0, newUser.balance);
            await createUserNotification(newUser._id, 'Bem-vindo à Foundry Invest!', `Você recebeu um bônus de registro de ${registrationBonusApplied.toFixed(2)} MT!`, 'success', '/wallet');
        }
        if (referredByUser) { await createUserNotification(referredByUser._id, 'Nova Indicação na Foundry!', `${newUser.name} registrou-se usando seu código de indicação.`, 'info', '/referrals'); }
        res.status(201).json({ m: 'Usuário registrado com sucesso!', userId: newUser._id });
    } catch (error) { console.error("[Foundry] Erro no registro:", error); if (error.name === 'ValidationError') { return res.status(400).json({ m: "Dados inválidos.", e: Object.values(error.errors).map(val => val.message) }); } res.status(500).json({ m: 'Erro no servidor ao registrar.' }); }
});
authRouter.post('/login', async (req, res) => { /* ... como no seu código original ... */ 
    try {
        const { email, password } = req.body; if (!email || !password) return res.status(400).json({ m: 'Email e senha são obrigatórios.' });
        const user = await User.findOne({ email: email.toLowerCase() }); if (!user) return res.status(401).json({ m: 'Credenciais inválidas.' });
        if (user.status !== 'active') return res.status(403).json({ m: `Sua conta está ${user.status}. Contacte o suporte.` });
        const MAX_FAILED_ATTEMPTS = 5; const LOCK_TIME = 15 * 60 * 1000; 
        if (user.lockUntil && user.lockUntil > Date.now()) { return res.status(403).json({ m: `Conta bloqueada. Tente novamente em ${Math.ceil((user.lockUntil - Date.now()) / 60000)} minutos.` }); }
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            user.failedLoginAttempts += 1;
            if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) { user.lockUntil = Date.now() + LOCK_TIME; await createUserNotification(user._id, "Conta Bloqueada", "Múltiplas tentativas de login falhadas.", 'error'); }
            await user.save(); return res.status(401).json({ m: 'Credenciais inválidas.' });
        }
        user.failedLoginAttempts = 0; user.lockUntil = undefined; user.lastLoginAt = Date.now(); await user.save();
        const payload = { user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        res.json({ m: "Login bem-sucedido!", token: token, user: payload.user });
    } catch (error) { console.error("[Foundry] Erro no login:", error); res.status(500).json({ m: 'Erro no servidor durante o login.' }); }
});
authRouter.post('/recover/request-question', async (req, res) => { /* ... como no seu código original ... */ 
    try{ const{email}=req.body; if(!email)return res.status(400).json({m:"Email obrigatório."}); const user=await User.findOne({email:email.toLowerCase()}).select('securityQuestion email'); if(!user)return res.status(404).json({m:"Email não encontrado."}); res.json({email:user.email,securityQuestion:user.securityQuestion});
    } catch(e){ console.error("[Foundry] Erro ao solicitar pergunta de segurança:", e); res.status(500).json({m:"Erro no servidor."}) }
});

// ATUALIZADO: Rota para verificar resposta de segurança E GERAR LINK DE LOGIN ÚNICO
authRouter.post('/recover/verify-answer-and-get-login-link', async(req,res)=>{
    try{
        const{email, securityAnswer}=req.body;
        if(!email||!securityAnswer)return res.status(400).json({m:"Email e resposta de segurança são obrigatórios."});
        
        const user = await User.findOne({email:email.toLowerCase()});
        if(!user)return res.status(404).json({m:"Usuário não encontrado."});

        const isAnswerMatch = await user.compareSecurityAnswer(securityAnswer);
        if(!isAnswerMatch)return res.status(401).json({m:"Resposta de segurança incorreta."});

        const oneTimeLoginToken = user.createOneTimeLoginToken(); // Método do schema User
        await user.save({validateBeforeSave:false}); 

        console.log(`[Foundry][AUTH] Token de login único gerado para ${user.email} (para admin/sistema enviar ao usuário): ${oneTimeLoginToken}`);
        res.json({
            m: "Resposta verificada. Um link de login único pode ser gerado com o token fornecido (válido por 15 minutos).",
            oneTimeLoginToken: oneTimeLoginToken 
        });
    } catch(e){ console.error("[Foundry] Erro ao verificar resposta e gerar OTLT:", e); res.status(500).json({m:"Erro no servidor."}) }
});

// NOVO: Rota para login com token de uso único
authRouter.post('/login-with-token', async (req, res) => {
    try {
        const { oneTimeLoginToken } = req.body;
        if (!oneTimeLoginToken) return res.status(400).json({ m: "Token de login único é obrigatório." });

        const hashedToken = crypto.createHash('sha256').update(oneTimeLoginToken).digest('hex');
        const user = await User.findOne({
            oneTimeLoginToken: hashedToken,
            oneTimeLoginTokenExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(401).json({ m: "Token de login único inválido ou expirado." });
        if (user.status !== 'active') return res.status(403).json({m:`Sua conta está ${user.status}. Contacte o suporte.`});

        user.oneTimeLoginToken = undefined;
        user.oneTimeLoginTokenExpires = undefined;
        user.lastLoginAt = Date.now();
        user.failedLoginAttempts = 0; 
        user.lockUntil = undefined;   
        await user.save();

        const payload = { user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status } };
        const regularJwtToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        
        await createUserNotification(user._id, "Acesso Concedido via Link", "Você acessou sua conta usando um link de login único.", 'success');
        res.json({ m: "Login com token bem-sucedido!", token: regularJwtToken, user: payload.user });

    } catch (error) {
        console.error("[Foundry] Erro no login com token único:", error);
        res.status(500).json({ m: "Erro no servidor ao tentar login com token." });
    }
});

// Rota de reset de senha tradicional (MANTIDA)
authRouter.post('/recover/reset-password', async (req, res) => { /* ... como no seu código original ... */ 
    try {
        const { token, newPassword, confirmNewPassword } = req.body;
        if (!token || !newPassword || !confirmNewPassword) return res.status(400).json({ m: "Token e novas senhas são obrigatórios." });
        if (newPassword.length < 6) return res.status(400).json({m:"Nova senha deve ter no mínimo 6 caracteres."});
        if (newPassword !== confirmNewPassword) return res.status(400).json({ m: "As novas senhas não coincidem." });
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetExpires: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ m: "Token de redefinição de senha inválido ou expirado." });
        user.password = newPassword; user.passwordResetToken = undefined; user.passwordResetExpires = undefined;
        user.failedLoginAttempts = 0; user.lockUntil = undefined;   
        await user.save();
        await createUserNotification(user._id,"Senha Redefinida com Sucesso","Sua senha foi redefinida e você já pode fazer login com a nova senha.",'success');
        res.json({ m: "Senha atualizada com sucesso. Você já pode fazer login." });
    } catch (error) { console.error("[Foundry] Erro ao redefinir senha:", error); res.status(500).json({ m: "Erro no servidor." }); }
});
app.use('/api/auth', authRouter);

// --- Rotas de Perfil do Usuário (/api/users) ---
const userRouter = express.Router();
userRouter.use(protectRoute); 
userRouter.get('/profile', async(req,res)=>{try{const u=await User.findById(req.user.id).select('-password -securityQuestion -securityAnswer -passwordResetToken -passwordResetExpires -failedLoginAttempts -lockUntil -__v -oneTimeLoginToken -oneTimeLoginTokenExpires');if(!u)return res.status(404).json({m:"Usuário não encontrado."});res.json(u);}catch(e){console.error("[Foundry] Erro perfil:",e);res.status(500).json({m:"Erro perfil."})}});
userRouter.put('/profile', async(req,res)=>{try{const{name}=req.body;const uD={};if(name&&name.trim().length>=3)uD.name=name.trim();else if(name)return res.status(400).json({m:"Nome < 3 chars."});if(Object.keys(uD).length===0)return res.status(400).json({m:"Nada para atualizar."});const u=await User.findByIdAndUpdate(req.user.id,uD,{new:true,runValidators:true}).select('-password -securityQuestion -securityAnswer -__v -oneTimeLoginToken -oneTimeLoginTokenExpires');if(!u)return res.status(404).json({m:"Usuário não encontrado."});currentUserData = u; localStorage.setItem('userData', JSON.stringify(u));res.json({m:"Perfil atualizado.",user:u});}catch(e){console.error("[Foundry] Erro atualizar perfil:",e);if(e.name==='ValidationError')return res.status(400).json({m:"Dados inválidos.",e:Object.values(e.errors).map(v=>v.message)});res.status(500).json({m:"Erro atualizar."})}});
userRouter.put('/change-password', async(req,res)=>{try{const{currentPassword,newPassword,confirmNewPassword}=req.body;if(!currentPassword||!newPassword||!confirmNewPassword)return res.status(400).json({m:"Campos obrigatórios."});if(newPassword.length<6)return res.status(400).json({m:"Senha < 6 chars."});if(newPassword!==confirmNewPassword)return res.status(400).json({m:"Senhas não coincidem."});const u=await User.findById(req.user.id);if(!u)return res.status(404).json({m:"Usuário não encontrado."});const iM=await u.comparePassword(currentPassword);if(!iM)return res.status(401).json({m:"Senha atual incorreta."});if(await bcrypt.compare(newPassword,u.password))return res.status(400).json({m:"Nova senha igual à atual."});u.password=newPassword;await u.save();await createUserNotification(u._id,"Senha Alterada","Sua senha foi alterada.",'success');res.json({m:"Senha alterada."});}catch(e){console.error("[Foundry] Erro alterar senha:",e);res.status(500).json({m:"Erro alterar senha."})}});
userRouter.get('/referral-details', async(req,res)=>{try{const u=await User.findById(req.user.id).select('referralCode');if(!u)return res.status(404).json({m:"Usuário não encontrado."});const rC=await User.countDocuments({referredBy:req.user.id});const rBR=await Transaction.aggregate([{$match:{user:new mongoose.Types.ObjectId(req.user.id),type:{$in:['referral_bonus_plan','referral_bonus_profit']}}},{$group:{_id:null,total:{$sum:'$amount'}}}]);res.json({rC:u.referralCode,tRU:rC,tRBE:rBR.length>0?rBR[0].total.toFixed(2):"0.00"});}catch(e){console.error("[Foundry] Erro detalhes indicação:",e);res.status(500).json({m:"Erro detalhes indicação."})}});
userRouter.get('/transactions', async(req,res)=>{try{const p=parseInt(req.query.page)||1;const l=parseInt(req.query.limit)||15;const s=(p-1)*l;const tF=req.query.type;let q={user:req.user.id};if(tF)q.type=tF;const ts=await Transaction.find(q).sort({transactionDate:-1}).skip(s).limit(l);const tT=await Transaction.countDocuments(q);res.json({transactions:ts,currentPage:p,totalPages:Math.ceil(tT/l),totalCount:tT});}catch(e){console.error("[Foundry] Erro transações:",e);res.status(500).json({m:"Erro transações."})}});
userRouter.get('/notifications', async(req,res)=>{try{const p=parseInt(req.query.page)||1;const l=parseInt(req.query.limit)||10;const s=(p-1)*l;const n=await Notification.find({user:req.user.id}).sort({createdAt:-1}).skip(s).limit(l);const tN=await Notification.countDocuments({user:req.user.id});const uC=await Notification.countDocuments({user:req.user.id,isRead:false});res.json({notifications:n,currentPage:p,totalPages:Math.ceil(tN/l),totalCount:tN,unreadCount:uC});}catch(e){console.error("[Foundry] Erro notificações:",e);res.status(500).json({m:"Erro notificações."})}});
userRouter.put('/notifications/:id/read', async(req,res)=>{try{if(!mongoose.Types.ObjectId.isValid(req.params.id))return res.status(400).json({m:"ID inválido."});const n=await Notification.findOneAndUpdate({_id:req.params.id,user:req.user.id},{isRead:true},{new:true});if(!n)return res.status(404).json({m:"Notificação não encontrada."});res.json({m:"Lida.",notification:n});}catch(e){console.error("[Foundry] Erro marcar lida:",e);res.status(500).json({m:"Erro."})}});
userRouter.put('/notifications/read-all', async(req,res)=>{try{await Notification.updateMany({user:req.user.id,isRead:false},{isRead:true});res.json({m:"Todas lidas."});}catch(e){console.error("[Foundry] Erro marcar todas lidas:",e);res.status(500).json({m:"Erro."})}});
app.use('/api/users', userRouter);

// --- ROTAS DE ADMIN ---
const adminRouter = express.Router();
adminRouter.use(protectRoute, adminOnly); 

// --- ROTAS ADMIN: CRUD PARA PLANOS (IMPLEMENTADAS/REVISADAS) ---
adminRouter.post('/plans', async (req, res) => { 
    try {
        const { name, price_mt, daily_profit_mt, duration_days, hashrate_mhs, description, icon_bs_class, isActive, features, maxInvestmentsPerUser } = req.body;
        if (!name || price_mt == null || daily_profit_mt == null || duration_days == null || hashrate_mhs == null) {
            return res.status(400).json({ m: "Campos obrigatórios para o plano (nome, preço, lucro diário, duração, hashrate) não fornecidos ou inválidos." });
        }
        const newPlan = new Plan({
            name, price_mt: parseFloat(price_mt), 
            daily_profit_mt: parseFloat(daily_profit_mt), 
            duration_days: parseInt(duration_days), 
            hashrate_mhs: parseFloat(hashrate_mhs), 
            description,
            icon_bs_class: icon_bs_class || 'bi-gem',
            isActive: isActive !== undefined ? isActive : true,
            features: Array.isArray(features) ? features : (features && typeof features === 'string' ? features.split(',').map(f=>f.trim()).filter(f => f) : []),
            maxInvestmentsPerUser: maxInvestmentsPerUser !== undefined ? parseInt(maxInvestmentsPerUser) : 1
        });
        await newPlan.save();
        console.log("[Foundry][ADMIN] Plano criado:", newPlan.name);
        res.status(201).json({ m: "Plano criado com sucesso!", plan: newPlan });
    } catch (error) {
        console.error("[Foundry] Erro ao criar plano (admin):", error);
        if (error.code === 11000) return res.status(400).json({m: "Um plano com este nome já existe."});
        if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)});
        res.status(500).json({ m: "Erro no servidor ao criar plano." });
    }
});
adminRouter.get('/plans/all', async (req, res) => { 
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10; 
        const skip = (page - 1) * limit;
        console.log("[Foundry][ADMIN] Buscando todos os planos...");
        const plans = await Plan.find({}).sort({ createdAt: -1 }).skip(skip).limit(limit);
        const totalPlans = await Plan.countDocuments({});
        console.log(`[Foundry][ADMIN] ${plans.length} planos encontrados na página ${page}. Total: ${totalPlans}`);
        res.json({ plans, currentPage: page, totalPages: Math.ceil(totalPlans / limit), totalCount: totalPlans });
    } catch (error) {
        console.error("[Foundry] Erro ao listar todos os planos (admin):", error);
        res.status(500).json({ m: "Erro ao listar planos." });
    }
});
adminRouter.get('/plans/:id', async (req, res) => { 
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ m: "ID de plano inválido." });
        console.log(`[Foundry][ADMIN] Buscando plano por ID: ${req.params.id}`);
        const plan = await Plan.findById(req.params.id);
        if (!plan) { console.warn(`[Foundry][ADMIN] Plano com ID ${req.params.id} não encontrado.`); return res.status(404).json({ m: "Plano não encontrado." }); }
        res.json(plan);
    } catch (error) { console.error("[Foundry] Erro ao buscar plano por ID (admin):", error); res.status(500).json({ m: "Erro ao buscar plano." }); }
});
adminRouter.put('/plans/:id', async (req, res) => { 
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ m: "ID de plano inválido." });
        const updateData = { ...req.body };
        if (updateData.features && typeof updateData.features === 'string') { updateData.features = updateData.features.split(',').map(f => f.trim()).filter(f => f); } 
        else if (updateData.features && !Array.isArray(updateData.features)) { delete updateData.features; }
        if (updateData.isActive !== undefined) { updateData.isActive = (updateData.isActive === true || String(updateData.isActive).toLowerCase() === 'true'); }
        ['price_mt', 'daily_profit_mt', 'duration_days', 'hashrate_mhs', 'maxInvestmentsPerUser'].forEach(field => { if (updateData[field] !== undefined && updateData[field] !== null && updateData[field] !== '') { updateData[field] = parseFloat(updateData[field]); } else if (updateData[field] === '') { delete updateData[field]; } });
        updateData.updatedAt = Date.now();
        console.log(`[Foundry][ADMIN] Atualizando plano ID ${req.params.id} com dados:`, JSON.stringify(updateData));
        const updatedPlan = await Plan.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true, runValidators: true });
        if (!updatedPlan) { console.warn(`[Foundry][ADMIN] Plano com ID ${req.params.id} não encontrado para atualização.`); return res.status(404).json({ m: "Plano não encontrado para atualização." }); }
        console.log("[Foundry][ADMIN] Plano atualizado:", updatedPlan.name);
        res.json({ m: "Plano atualizado com sucesso!", plan: updatedPlan });
    } catch (error) { console.error("[Foundry] Erro ao atualizar plano (admin):", error); if (error.code === 11000) return res.status(400).json({m: "Um plano com este nome já existe."}); if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)}); res.status(500).json({ m: "Erro no servidor ao atualizar plano." }); }
});
adminRouter.delete('/plans/:id', async (req, res) => { 
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ m: "ID de plano inválido." });
        const activeInvestments = await UserInvestment.countDocuments({ plan: req.params.id, isActive: true });
        if (activeInvestments > 0) { return res.status(400).json({m: `Não é possível deletar. Existem ${activeInvestments} investimentos ativos usando este plano. Desative-o primeiro.`}); }
        console.log(`[Foundry][ADMIN] Deletando plano ID ${req.params.id}`);
        const deletedPlan = await Plan.findByIdAndDelete(req.params.id);
        if (!deletedPlan) { console.warn(`[Foundry][ADMIN] Plano com ID ${req.params.id} não encontrado para deleção.`); return res.status(404).json({ m: "Plano não encontrado para deleção." }); }
        console.log("[Foundry][ADMIN] Plano deletado:", deletedPlan.name);
        res.json({ m: "Plano deletado com sucesso." });
    } catch (error) { console.error("[Foundry] Erro ao deletar plano (admin):", error); res.status(500).json({ m: "Erro no servidor ao deletar plano." }); }
});

// --- ROTA ADMIN: ATRIBUIR PLANO A USUÁRIO ---
adminRouter.post('/users/:userId/assign-plan', async (req, res) => { 
    try {
        const { userId } = req.params; const { planId, adminNotes } = req.body;
        if (!mongoose.Types.ObjectId.isValid(userId) || !mongoose.Types.ObjectId.isValid(planId)) return res.status(400).json({m: "ID de usuário ou plano inválido."});
        const user = await User.findById(userId); if (!user) return res.status(404).json({m: "Usuário não encontrado."});
        const plan = await Plan.findById(planId); if (!plan || !plan.isActive) return res.status(404).json({m: "Plano não encontrado ou inativo."});
        
        const startDate = new Date();
        const endDate = new Date(startDate.getTime() + plan.duration_days * 24 * 60 * 60 * 1000);
        let firstCollection = new Date(startDate);
        firstCollection.setUTCDate(firstCollection.getUTCDate() + 1); 
        firstCollection.setUTCHours(PROFIT_COLLECTION_START_HOUR - TIMEZONE_OFFSET_HOURS, 0, 0, 0); 

        const newInvestment = new UserInvestment({ 
            user: user._id, plan: plan._id, 
            planSnapshot: { name: plan.name, price_mt: plan.price_mt, daily_profit_mt: plan.daily_profit_mt, duration_days: plan.duration_days },
            startDate: startDate,
            endDate: endDate,
            lastProfitCalculationTime: startDate,
            nextCollectionAvailableAt: firstCollection
        });
        await newInvestment.save();
        const transactionDescription = `Plano "${plan.name}" atribuído pelo administrador. ${adminNotes ? 'Nota: ' + adminNotes : ''}`;
        await createTransactionEntry( user._id, 'admin_plan_assignment', 0, transactionDescription, 'completed', user.balance, user.balance, { relatedInvestment: newInvestment._id });
        
        const systemSettings = await getOrInitializeSystemSettings();
        if (!user.canWithdrawBonus && systemSettings.bonusWithdrawalRequiresPlan) { 
            user.canWithdrawBonus = true; 
            await user.save(); 
            console.log(`[Foundry][ADMIN] Usuário ${user.name} agora pode sacar bônus após atribuição de plano.`);
        }
        await createUserNotification(user._id, 'Novo Plano Atribuído!', `O plano "${plan.name}" foi atribuído à sua conta por um administrador.`, 'investment', '/investments/my-active');
        res.status(201).json({m: `Plano "${plan.name}" atribuído com sucesso ao usuário ${user.name}.`, investment: newInvestment});
    } catch (error) { console.error("[Foundry] Erro ao atribuir plano (admin):", error); res.status(500).json({m: "Erro no servidor ao atribuir plano."}); }
});
// --- ROTA ADMIN: INICIAR RESET DE SENHA TRADICIONAL PARA USUÁRIO ---
adminRouter.post('/users/:userId/initiate-password-reset', async (req, res) => {
    try {
        const { userId } = req.params; if (!mongoose.Types.ObjectId.isValid(userId)) return res.status(400).json({m: "ID de usuário inválido."});
        const user = await User.findById(userId); if (!user) return res.status(404).json({m: "Usuário não encontrado."});
        const resetToken = user.createPasswordResetToken(); await user.save({ validateBeforeSave: false });
        console.log(`[Foundry][ADMIN] Token de reset de senha (tradicional) gerado para ${user.email}: ${resetToken} (para admin enviar ao usuário)`);
        await createUserNotification(user._id, 'Redefinição de Senha Iniciada', 'Um administrador iniciou um processo de redefinição de senha para sua conta. Siga as instruções fornecidas.', 'warning');
        res.json({m: `Processo de redefinição de senha iniciado para ${user.email}. O usuário precisa seguir as instruções. Token (para admin): ${resetToken}`});
    } catch (error) { console.error("[Foundry] Erro ao iniciar reset de senha pelo admin:", error); res.status(500).json({m: "Erro no servidor."}); }
});

// Outras rotas de admin (/api/admin/*)
adminRouter.get('/settings',async(req,res)=>{ /* ... como antes ... */ try{const s=await getOrInitializeSystemSettings();res.json(s);}catch(e){console.error("[Foundry] Erro ao buscar config:",e);res.status(500).json({m:"Erro ao buscar config."})} });
adminRouter.put('/settings',async(req,res)=>{ /* ... como antes, com validação melhorada ... */ 
    try {
        const updates = req.body; 
        const validNumberFields = ['registrationBonusAmount', 'referralPlanPurchaseBonusPercentage', 'referralDailyProfitBonusPercentage', 'minWithdrawalAmount', 'maxWithdrawalAmount', 'withdrawalFeePercentage', 'defaultPlanDuration']; 
        const validBooleanFields = ['isReferralSystemActive', 'isRegistrationBonusActive', 'bonusWithdrawalRequiresPlan']; 
        const settings = await SystemSettings.findOne({ singletonId: 'main_settings' }); 
        if (!settings) return res.status(404).json({ m: "Configurações do sistema não encontradas." }); 
        for (const key in updates) { 
            if (Object.prototype.hasOwnProperty.call(settings, key) && key !== 'singletonId' && key !== '_id' && key !== '__v' && key !== 'lastUpdatedAt') { 
                 if (validNumberFields.includes(key)) { 
                    const numValue = parseFloat(updates[key]); 
                    if (!isNaN(numValue) && numValue >= 0 && (key.includes('Percentage') ? numValue <= 1 : true) ) { settings[key] = numValue; }  
                    else { return res.status(400).json({m: `Valor inválido para ${key}.`});} 
                } else if (validBooleanFields.includes(key)) { settings[key] = (updates[key] === true || String(updates[key]).toLowerCase() === 'true'); } 
            }
        }
        settings.lastUpdatedAt = Date.now(); await settings.save(); 
        res.json({ m: "Configurações do sistema atualizadas!", settings: settings }); 
    } catch (error) { console.error("[Foundry] Erro ao atualizar configurações:", error); res.status(500).json({ m: "Erro ao atualizar configurações." }); } 
});
adminRouter.get('/users',async(req,res)=>{ /* ... como antes ... */  
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 15; const skip = (page - 1) * limit; 
        const { search, role, status, sortBy = 'createdAt', sortOrder = 'desc' } = req.query; 
        let query = {}; 
        if (search) { query.$or = [ { name: { $regex: search, $options: 'i' } }, { email: { $regex: search, $options: 'i' } } ]; } 
        if (role) query.role = role; if (status) query.status = status; 
        const sortOptions = {}; sortOptions[sortBy] = sortOrder === 'asc' ? 1 : -1; 
        const users = await User.find(query).select('-password -securityAnswer').sort(sortOptions).skip(skip).limit(limit).populate('referredBy', 'name email'); 
        const totalUsers = await User.countDocuments(query); 
        res.json({ users: users, currentPage: page, totalPages: Math.ceil(totalUsers / limit), totalCount: totalUsers }); 
    } catch (error) { console.error("[Foundry] Erro ao listar usuários (admin):", error); res.status(500).json({ m: "Erro ao listar usuários." }); } 
});
adminRouter.get('/users/:id',async(req,res)=>{ /* ... como antes ... */  
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de usuário inválido."}); 
        const user = await User.findById(req.params.id).select('-password -securityAnswer -oneTimeLoginToken -oneTimeLoginTokenExpires').populate('referredBy', 'name email'); 
        if (!user) return res.status(404).json({ m: "Usuário não encontrado." }); 
        const investments = await UserInvestment.find({user: user._id}).populate('plan', 'name price_mt').sort({startDate: -1}); 
        const transactions = await Transaction.find({user: user._id}).sort({transactionDate: -1}).limit(20);  
        const withdrawalRequests = await WithdrawalRequest.find({user: user._id}).sort({requestedAt: -1}).limit(10); 
        const depositRequests = await DepositRequest.find({user: user._id}).sort({requestedAt: -1}).limit(10); 
        res.json({ user: user, investments, transactions, withdrawalRequests, depositRequests }); 
    } catch (error) { console.error("[Foundry] Erro ao buscar detalhes do usuário (admin):", error); res.status(500).json({ m: "Erro ao buscar detalhes do usuário." }); } 
});
adminRouter.put('/users/:id/update-details',async(req,res)=>{ /* ... como antes com canWithdrawBonus ... */  
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de usuário inválido."}); 
        const { name, email, role, status, balanceAdjustment, adjustmentReason, canWithdrawBonus } = req.body; 
        const user = await User.findById(req.params.id); if (!user) return res.status(404).json({ m: "Usuário não encontrado." }); 
        let emailChanged = false; 
        if (name && name.trim() !== '') user.name = name.trim(); 
        if (email && email.toLowerCase() !== user.email) { 
            const existingEmailUser = await User.findOne({ email: email.toLowerCase() }); 
            if (existingEmailUser && existingEmailUser._id.toString() !== user._id.toString()) { return res.status(400).json({ m: "Este email já está em uso por outro usuário." }); } 
            user.email = email.toLowerCase(); emailChanged = true; 
        }
        if (role && ['user', 'admin'].includes(role)) user.role = role; 
        if (status && ['active', 'suspended', 'banned', 'pending_verification'].includes(status)) { if (user.status !== status && status === 'active') { user.failedLoginAttempts = 0; user.lockUntil = null; } user.status = status; } 
        if (typeof canWithdrawBonus === 'boolean') user.canWithdrawBonus = canWithdrawBonus; // Atualiza canWithdrawBonus
        if (balanceAdjustment !== undefined && typeof balanceAdjustment === 'number' && balanceAdjustment !== 0) { 
            if (!adjustmentReason || adjustmentReason.trim() === '') { return res.status(400).json({m: "A razão para o ajuste de saldo é obrigatória."}); } 
            const oldBalance = user.balance; const newBalance = user.balance + balanceAdjustment; 
            if (newBalance < 0) return res.status(400).json({m: "Ajuste resultaria em saldo negativo."}); 
            user.balance = newBalance; 
            await createTransactionEntry(user._id, balanceAdjustment > 0 ? 'admin_credit' : 'admin_debit', balanceAdjustment, `Ajuste de Administrador: ${adjustmentReason}`, 'completed', oldBalance, newBalance); 
            await createUserNotification(user._id, "Saldo Ajustado pelo Administrador", `Seu saldo foi ajustado em ${balanceAdjustment.toFixed(2)} MT. Razão: ${adjustmentReason}.`, 'info'); 
        }
        await user.save(); 
        const userToReturn = user.toObject(); delete userToReturn.password; delete userToReturn.securityAnswer; delete userToReturn.oneTimeLoginToken; delete userToReturn.oneTimeLoginTokenExpires;
        res.json({ m: "Detalhes do usuário atualizados.", user: userToReturn, emailChanged: emailChanged }); 
    } catch (error) { console.error("[Foundry] Erro ao atualizar detalhes do usuário (admin):", error); res.status(500).json({ m: "Erro ao atualizar detalhes do usuário." }); } 
});
adminRouter.put('/users/:id/status',async(req,res)=>{ /* ... como antes ... */  
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de usuário inválido."}); 
        const { status, reason } = req.body; 
        if (!status || !['active', 'suspended', 'banned'].includes(status)) { return res.status(400).json({m: "Status fornecido é inválido. Use 'active', 'suspended', ou 'banned'."}); } 
        const user = await User.findById(req.params.id); if (!user) return res.status(404).json({m: "Usuário não encontrado."}); 
        if (user.role === 'admin' && status !== 'active') { 
            const activeAdminCount = await User.countDocuments({role: 'admin', status: 'active'}); 
            if (activeAdminCount <= 1 && user.id === req.user.id) { return res.status(400).json({m: "Não é possível desativar o único administrador ativo."}); } 
        }
        user.status = status; if (status === 'active') { user.failedLoginAttempts = 0; user.lockUntil = null; } 
        await user.save(); 
        await createUserNotification(user._id, "Status da Sua Conta Alterado", `O status da sua conta foi alterado para: ${status}. ${reason ? 'Razão: '+reason : ''}`, status === 'active' ? 'success' : 'warning'); 
        const userToReturn = user.toObject(); delete userToReturn.password; delete userToReturn.securityAnswer; 
        res.json({ m: `Status do usuário alterado para ${status}.`, user: userToReturn }); 
    } catch (error) { console.error("[Foundry] Erro ao alterar status do usuário (admin):", error); res.status(500).json({ m: "Erro ao alterar status do usuário." }); } 
});
adminRouter.post('/deposit-methods',async(req,res)=>{ /* ... como antes ... */  
    try {
        const { name, instructions, paymentInfo } = req.body; 
        if (!name || !instructions || !paymentInfo ) return res.status(400).json({m: "Nome, instruções e informações de pagamento são obrigatórios."}); 
        const newMethod = new DepositMethod(req.body); await newMethod.save(); 
        res.status(201).json({ m: "Novo método de depósito adicionado.", method: newMethod }); 
    } catch (error) { if (error.code === 11000) return res.status(400).json({m: "Um método de depósito com este nome já existe."}); console.error("[Foundry] Erro ao adicionar método de depósito:", error); res.status(500).json({ m: "Erro ao adicionar método de depósito." }); } 
});
adminRouter.get('/deposit-methods',async(req,res)=>{ /* ... como antes ... */  
    try { const methods = await DepositMethod.find().sort({ name: 1 }); res.json(methods); 
    } catch (error) { console.error("[Foundry] Erro ao listar métodos de depósito:", error); res.status(500).json({ m: "Erro ao listar métodos de depósito." }); } 
});
adminRouter.put('/deposit-methods/:id',async(req,res)=>{ /* ... como antes ... */  
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de método inválido."}); 
        const updatedMethod = await DepositMethod.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true }); 
        if (!updatedMethod) return res.status(404).json({m: "Método de depósito não encontrado."}); 
        res.json({ m: "Método de depósito atualizado.", method: updatedMethod }); 
    } catch (error) { if (error.code === 11000) return res.status(400).json({m: "Um método de depósito com este nome já existe."}); console.error("[Foundry] Erro ao atualizar método de depósito:", error); res.status(500).json({ m: "Erro ao atualizar método de depósito." }); } 
});
adminRouter.delete('/deposit-methods/:id',async(req,res)=>{ /* ... como antes ... */  
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de método inválido."}); 
        const deletedMethod = await DepositMethod.findByIdAndDelete(req.params.id); 
        if (!deletedMethod) return res.status(404).json({m: "Método de depósito não encontrado."}); 
        res.json({ m: "Método de depósito removido." }); 
    } catch (error) { console.error("[Foundry] Erro ao remover método de depósito:", error); res.status(500).json({ m: "Erro ao remover método de depósito." }); } 
});
adminRouter.get('/deposit-requests',async(req,res)=>{ /* ... como antes ... */  
    try {
        const { status, page = 1, limit = 10 } = req.query; const query = status ? { status } : {}; 
        const requests = await DepositRequest.find(query).populate('user', 'name email').populate('depositMethod', 'name').sort({ requestedAt: -1 }).limit(parseInt(limit)).skip((parseInt(page) - 1) * parseInt(limit)); 
        const count = await DepositRequest.countDocuments(query); 
        res.json({ requests: requests, totalPages: Math.ceil(count / limit), currentPage: parseInt(page) });  
    } catch (error) { console.error("[Foundry] Erro ao buscar solicitações de depósito (admin):", error); res.status(500).json({ m: "Erro ao buscar solicitações de depósito." }); } 
});
adminRouter.put('/deposit-requests/:id/process',async(req,res)=>{ /* ... como antes ... */  
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de solicitação inválido."}); 
        const { status, adminNotes } = req.body;  
        if (!['approved', 'rejected'].includes(status)) { return res.status(400).json({m: "Status inválido. Deve ser 'approved' ou 'rejected'."}); } 
        const request = await DepositRequest.findById(req.params.id).populate('depositMethod', 'name'); 
        if (!request || request.status !== 'pending') { return res.status(404).json({m: "Solicitação não encontrada ou já processada."}); } 
        request.status = status; request.adminNotes = adminNotes || ''; request.processedAt = Date.now(); 
        const user = await User.findById(request.user); if (!user) return res.status(404).json({m: "Usuário da solicitação não encontrado."}); 
        if (status === 'approved') { 
            const balanceBefore = user.balance; user.balance += request.amount; await user.save(); 
            await createTransactionEntry(user._id, 'deposit_approved', request.amount, `Depósito Aprovado via ${request.depositMethod?.name || 'N/A'}. Ref: ${request.userTransactionReference}`, 'completed', balanceBefore, user.balance, {relatedDepositRequest: request._id}); 
            await createUserNotification(user._id, "Depósito Aprovado", `Seu depósito de ${request.amount.toFixed(2)} MT foi aprovado e creditado em sua conta.`, 'success', '/transactions'); 
        } else { request.rejectionReason = adminNotes || 'Não especificado pelo administrador.'; await createUserNotification(user._id, "Depósito Rejeitado", `Sua solicitação de depósito de ${request.amount.toFixed(2)} MT foi rejeitada. Razão: ${request.rejectionReason}`, 'error'); } 
        await request.save(); 
        res.json({ m: `Solicitação de depósito marcada como ${status}.`, request: request }); 
    } catch (error) { console.error("[Foundry] Erro ao processar solicitação de depósito (admin):", error); res.status(500).json({ m: "Erro ao processar solicitação." }); } 
});
adminRouter.get('/withdrawal-requests',async(req,res)=>{ /* ... como antes ... */  
    try {
        const { status, page = 1, limit = 10 } = req.query; const query = status ? { status } : {}; 
        const requests = await WithdrawalRequest.find(query).populate('user', 'name email balance').sort({ requestedAt: -1 }).limit(parseInt(limit)).skip((parseInt(page) - 1) * parseInt(limit)); 
        const count = await WithdrawalRequest.countDocuments(query); 
        res.json({ requests: requests, totalPages: Math.ceil(count / limit), currentPage: parseInt(page) });  
    } catch (error) { console.error("[Foundry] Erro ao buscar solicitações de saque (admin):", error); res.status(500).json({ m: "Erro ao buscar solicitações de saque." }); } 
});
adminRouter.put('/withdrawal-requests/:id/process',async(req,res)=>{ /* ... como antes ... */  
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de solicitação inválido."}); 
        const { status, adminNotes, transactionIdFromProvider } = req.body; 
        if (!['approved', 'processing', 'completed', 'rejected', 'failed'].includes(status)) { return res.status(400).json({m: "Status de saque inválido."}); } 
        const request = await WithdrawalRequest.findById(req.params.id); if (!request) return res.status(404).json({m: "Solicitação de saque não encontrada."}); 
        const user = await User.findById(request.user); if (!user) return res.status(404).json({m: "Usuário da solicitação não encontrado."}); 
        const oldStatus = request.status; request.status = status; request.adminNotes = adminNotes || request.adminNotes;  
        if (transactionIdFromProvider) request.transactionIdFromProvider = transactionIdFromProvider; 
        let notificationMessage = ''; let notificationType = 'info'; 
        if (status === 'approved' && oldStatus === 'pending') { request.processedAt = Date.now(); notificationMessage = `Sua solicitação de saque de ${request.amount.toFixed(2)} MT foi aprovada e está aguardando processamento pelo provedor.`; notificationType = 'success'; 
        } else if (status === 'processing' && oldStatus !== 'processing') { request.processedAt = Date.now(); notificationMessage = `Sua solicitação de saque de ${request.amount.toFixed(2)} MT está sendo processada.`; notificationType = 'info'; 
        } else if (status === 'completed' && oldStatus !== 'completed') { 
            if (user.balance < request.amount) { request.status = 'failed'; request.rejectionReason = 'Saldo insuficiente no momento do processamento final.'; await request.save(); await createUserNotification(user._id,"Falha no Saque",`Saque de ${request.amount.toFixed(2)} MT falhou por saldo insuficiente no processamento final.`,'error'); return res.status(400).json({m:"Saldo do usuário tornou-se insuficiente."}); } 
            const balanceBefore = user.balance; user.balance -= request.amount; await user.save(); 
            request.completedAt = Date.now(); 
            await createTransactionEntry(user._id, 'withdrawal_processed', -request.amount, `Saque de ${request.amount.toFixed(2)} MT (${request.withdrawalMethodType}) processado.`, 'completed', balanceBefore, user.balance, {relatedWithdrawalRequest: request._id}); 
            notificationMessage = `Seu saque de ${request.amount.toFixed(2)} MT foi concluído com sucesso.`; notificationType = 'success'; 
        } else if (status === 'rejected' || status === 'failed') { request.rejectionReason = adminNotes || (status === 'rejected' ? 'Rejeitado pelo administrador.' : 'Falha no processamento.'); notificationMessage = `Sua solicitação de saque de ${request.amount.toFixed(2)} MT foi ${status === 'rejected' ? 'rejeitada' : 'marcada como falha'}. Razão: ${request.rejectionReason}`; notificationType = 'error'; } 
        await request.save(); 
        if (notificationMessage) { await createUserNotification(user._id, "Atualização do Status de Saque", notificationMessage, notificationType, '/transactions'); } 
        res.json({ m: `Status da solicitação de saque atualizado para ${status}.`, request: request }); 
    } catch (error) { console.error("[Foundry] Erro ao processar solicitação de saque (admin):", error); res.status(500).json({ m: "Erro ao processar solicitação de saque." }); } 
});
adminRouter.get('/investments', async (req, res) => { /* ... como antes ... */  
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 15; const skip = (page - 1) * limit; 
        const { userId, planId, isActive, sort = '-startDate' } = req.query;  
        let query = {}; if (userId && mongoose.Types.ObjectId.isValid(userId)) query.user = userId; if (planId && mongoose.Types.ObjectId.isValid(planId)) query.plan = planId; if (isActive !== undefined) query.isActive = (isActive === 'true'); 
        const investments = await UserInvestment.find(query).populate('user', 'name email').populate('plan', 'name').sort(sort).skip(skip).limit(limit); 
        const totalInvestments = await UserInvestment.countDocuments(query); 
        res.json({ investments: investments, currentPage: page, totalPages: Math.ceil(totalInvestments / limit), totalCount: totalInvestments }); 
    } catch (error) { console.error("[Foundry] Erro ao listar investimentos (admin):", error); res.status(500).json({ m: "Erro ao listar investimentos." }); } 
});
adminRouter.get('/investments/:id', async (req, res) => { /* ... como antes ... */  
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de investimento inválido."}); 
        const investment = await UserInvestment.findById(req.params.id).populate('user', 'name email balance').populate('plan');  
        if (!investment) return res.status(404).json({m: "Investimento não encontrado."}); res.json(investment); 
    } catch (error) { console.error("[Foundry] Erro ao buscar detalhe do investimento (admin):", error); res.status(500).json({ m: "Erro ao buscar detalhe do investimento." }); } 
});
adminRouter.put('/investments/:id/status', async (req, res) => { /* ... como antes ... */  
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de investimento inválido."}); 
        const { isActive, adminNotes } = req.body; if (typeof isActive !== 'boolean') { return res.status(400).json({m: "O campo 'isActive' (booleano) é obrigatório."}); } 
        const investment = await UserInvestment.findById(req.params.id).populate('planSnapshot');  
        if (!investment) return res.status(404).json({m: "Investimento não encontrado."}); 
        investment.isActive = isActive; await investment.save(); 
        await createUserNotification(investment.user, `Status do Investimento Alterado`, `Seu plano de investimento "${investment.planSnapshot.name}" foi marcado como ${isActive ? 'Ativo' : 'Inativo'} pelo administrador. ${adminNotes || ''}`, isActive ? 'info' : 'warning'); 
        res.json({ m: "Status do investimento atualizado.", investment: investment }); 
    } catch (error) { console.error("[Foundry] Erro ao atualizar status do investimento (admin):", error); res.status(500).json({ m: "Erro ao atualizar status do investimento." }); } 
});
adminRouter.get('/stats/overview', async(req,res)=>{ /* ... como antes ... */  
    try {
        const totalUsers = await User.countDocuments(); const totalActiveSystemPlans = await Plan.countDocuments({isActive: true}); 
        const totalActiveUserInvestments = await UserInvestment.countDocuments({isActive: true}); 
        const totalDepositsResult = await Transaction.aggregate([ {$match:{type:'deposit_approved'}}, {$group:{_id:null,total:{$sum:'$amount'}}} ]); 
        const totalWithdrawalsResult = await WithdrawalRequest.aggregate([ {$match:{status:'completed'}}, {$group:{_id:null,total:{$sum:'$netAmount'}}} ]);  
        const totalProfitsCollectedResult = await Transaction.aggregate([ {$match:{type:'profit_collection'}}, {$group:{_id:null,total:{$sum:'$amount'}}} ]); 
        const pendingWithdrawals = await WithdrawalRequest.countDocuments({status: 'pending'}); const pendingDeposits = await DepositRequest.countDocuments({status: 'pending'}); 
        res.json({ totalUsers, totalActiveSystemPlans, totalActiveUserInvestments, totalDeposited: totalDepositsResult[0]?.total || 0, totalWithdrawn: totalWithdrawalsResult[0]?.total || 0, totalProfitsCollectedByUsers: totalProfitsCollectedResult[0]?.total || 0, pendingWithdrawalRequests: pendingWithdrawals, pendingDepositRequests: pendingDeposits }); 
    } catch(error) { console.error("[Foundry] Erro ao buscar estatísticas gerais:", error); res.status(500).json({m:"Erro ao buscar estatísticas."}); } 
});
adminRouter.get('/stats/user-growth', async(req,res)=>{ /* ... como antes ... */  
    try{
        const days = parseInt(req.query.days) || 30; const today = new Date(); today.setUTCHours(0,0,0,0);  
        const dateLimit = new Date(today); dateLimit.setDate(today.getDate() - days); 
        const userGrowth = await User.aggregate([ {$match:{ createdAt: {$gte: dateLimit} }}, {$group:{ _id: { $dateToString:{format:"%Y-%m-%d", date:"$createdAt", timezone: "Africa/Maputo"} }, count: {$sum:1} }}, {$sort:{_id:1}} ]); 
        res.json(userGrowth); 
    }catch(error){ console.error("[Foundry] Erro ao buscar estatísticas de crescimento de usuários:", error); res.status(500).json({m:"Erro ao buscar estatísticas de crescimento."}); } 
});

// Rotas Admin para Contadores Regressivos
adminRouter.post('/countdowns', async (req, res) => { 
    try { 
        const { title, description, targetDate, isActive, actionLink, displayLocation } = req.body; 
        if (!title || !targetDate) { return res.status(400).json({ m: "Título e Data Alvo são obrigatórios para o contador." }); } 
        const newCountdown = new Countdown({ title, description, targetDate: new Date(targetDate), isActive, actionLink, displayLocation }); 
        await newCountdown.save(); 
        res.status(201).json({ m: "Contador regressivo criado com sucesso!", countdown: newCountdown }); 
    } catch (error) { console.error("[Foundry] Erro ao criar countdown (admin):", error); if (error.name === 'ValidationError') return res.status(400).json({m: "Dados inválidos.", e: Object.values(error.errors).map(v=>v.message)}); res.status(500).json({ m: "Erro no servidor ao criar contador." }); } 
});
adminRouter.get('/countdowns/all', async (req, res) => { 
    try { const countdowns = await Countdown.find().sort({ targetDate: -1 }); res.json(countdowns); 
    } catch (error) { console.error("[Foundry] Erro ao listar countdowns (admin):", error); res.status(500).json({ m: "Erro ao buscar contadores." }); } 
});
adminRouter.put('/countdowns/:id', async (req, res) => { 
    try { 
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de contador inválido."}); 
        const updateData = { ...req.body }; 
        if (updateData.targetDate) updateData.targetDate = new Date(updateData.targetDate); 
        if (updateData.isActive !== undefined) updateData.isActive = (updateData.isActive === true || String(updateData.isActive).toLowerCase() === 'true'); 
        const updatedCountdown = await Countdown.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true, runValidators: true }); 
        if (!updatedCountdown) return res.status(404).json({m: "Contador não encontrado para atualização."}); 
        res.json({ m: "Contador atualizado com sucesso!", countdown: updatedCountdown }); 
    } catch (error) { console.error("[Foundry] Erro ao atualizar countdown (admin):", error); if (error.name === 'ValidationError') return res.status(400).json({m: "Dados inválidos.", e: Object.values(error.errors).map(v=>v.message)}); res.status(500).json({ m: "Erro no servidor ao atualizar contador." }); } 
});
adminRouter.delete('/countdowns/:id', async (req, res) => { 
    try { 
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de contador inválido."}); 
        const deletedCountdown = await Countdown.findByIdAndDelete(req.params.id); 
        if (!deletedCountdown) return res.status(404).json({m: "Contador não encontrado para deleção."}); 
        res.json({ m: "Contador deletado com sucesso." }); 
    } catch (error) { console.error("[Foundry] Erro ao deletar countdown (admin):", error); res.status(500).json({ m: "Erro no servidor ao deletar contador." }); } 
});
app.use('/api/admin', adminRouter); 


// --- Rotas Públicas (Planos, Métodos de Depósito, Blog público, Promoções públicas, Countdowns públicos) ---
const publicPlanRouter = express.Router();
publicPlanRouter.get('/',async(req,res)=>{ try { const plans = await Plan.find({ isActive: true }).sort({ price_mt: 1 }); res.json(plans); } catch (error) { console.error("[Foundry] Erro ao buscar planos públicos:", error); res.status(500).json({ m: "Erro ao buscar planos." }); } });
publicPlanRouter.get('/:id',async(req,res)=>{ try { if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de plano inválido."}); const plan = await Plan.findById(req.params.id); if (!plan || !plan.isActive) return res.status(404).json({ m: "Plano não encontrado ou inativo." }); res.json(plan); } catch (error) { console.error("[Foundry] Erro ao buscar plano público por ID:", error); res.status(500).json({ m: "Erro ao buscar plano." }); } });
app.use('/api/plans', publicPlanRouter);

const publicDepositMethodRouter = express.Router();
publicDepositMethodRouter.get('/', async(req,res)=>{ try { const methods = await DepositMethod.find({ isActive: true }).select('-createdAt -updatedAt -__v -accountDetailsSchema'); res.json(methods); } catch (error) { console.error("[Foundry] Erro ao buscar métodos de depósito públicos:", error); res.status(500).json({ m: "Erro ao buscar métodos de depósito." }); } });
app.use('/api/deposit-methods', publicDepositMethodRouter); 

const blogRouter = express.Router();
blogRouter.post('/', protectRoute, adminOnly, async (req, res) => { /* ... como no seu código original ... */ 
    try {
        const { title, content, slug, snippet, tags, isPublished, coverImageUrl } = req.body;
        if (!title || !content) return res.status(400).json({m: "Título e conteúdo são obrigatórios para o post."});
        let postSlug = slug; if (!postSlug || postSlug.trim() === '') { postSlug = title.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, ''); }
        const existingSlug = await BlogPost.findOne({ slug: postSlug, _id: { $ne: req.body.postId } }); // Verifica se o slug já existe em outro post
        if (existingSlug) return res.status(400).json({m: "Este slug já está em uso. Escolha outro."});
        const newPost = new BlogPost({ title, content, slug: postSlug, snippet: snippet || (content.length > 250 ? content.substring(0, 250) + '...' : content), tags: Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t=>t.trim()).filter(t => t) : []), isPublished: isPublished === true, coverImageUrl, author: req.user.id });
        await newPost.save(); res.status(201).json({ m: "Post do blog criado com sucesso!", post: newPost });
    } catch (error) { console.error("[Foundry] Erro ao criar post:", error); if (error.code === 11000) return res.status(400).json({m: "Um post com este título ou slug já existe."}); if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)}); res.status(500).json({ m: "Erro no servidor ao criar post." }); }
});
blogRouter.get('/', async (req, res) => { /* ... como no seu código original (rota pública) ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 10; const skip = (page - 1) * limit;
        const tagFilter = req.query.tag; const searchQuery = req.query.search;
        let query = { isPublished: true }; if (tagFilter) query.tags = tagFilter.trim().toLowerCase(); if (searchQuery) query.title = { $regex: searchQuery, $options: 'i' }; 
        const posts = await BlogPost.find(query).populate('author', 'name').sort({ createdAt: -1 }).skip(skip).limit(limit).select('title slug snippet tags createdAt coverImageUrl author views'); 
        const totalPosts = await BlogPost.countDocuments(query);
        res.json({ posts: posts, currentPage: page, totalPages: Math.ceil(totalPosts / limit), totalCount: totalPosts });
    } catch (error) { console.error("[Foundry] Erro ao buscar posts (público):", error); res.status(500).json({ m: "Erro ao buscar posts do blog." }); }
});
blogRouter.get('/all', protectRoute, adminOnly, async (req, res) => { /* ... como no seu código original (rota admin) ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 20; const skip = (page - 1) * limit;
        const { isPublished, search } = req.query; let query = {};
        if (isPublished !== undefined) query.isPublished = (isPublished === 'true'); if (search) query.title = { $regex: search, $options: 'i' };
        const posts = await BlogPost.find(query).populate('author', 'name').sort({ createdAt: -1 }).skip(skip).limit(limit);
        const totalPosts = await BlogPost.countDocuments(query);
        res.json({ posts: posts, currentPage: page, totalPages: Math.ceil(totalPosts / limit), totalCount: totalPosts });
    } catch (error) { console.error("[Foundry] Erro ao buscar todos os posts (admin):", error); res.status(500).json({ m: "Erro ao buscar posts." }); }
});
blogRouter.get('/slug/:slug', async (req, res) => { /* ... como no seu código original (rota pública) ... */ 
    try {
        const post = await BlogPost.findOneAndUpdate( { slug: req.params.slug.toLowerCase(), isPublished: true }, { $inc: { views: 1 } }, { new: true } ).populate('author', 'name');
        if (!post) return res.status(404).json({ m: "Post do blog não encontrado ou não publicado." }); res.json(post);
    } catch (error) { console.error("[Foundry] Erro ao buscar post por slug:", error); res.status(500).json({ m: "Erro ao buscar post." }); }
});
blogRouter.get('/id/:id', protectRoute, adminOnly, async (req, res) => { /* ... como no seu código original (rota admin) ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de post inválido."});
        const post = await BlogPost.findById(req.params.id).populate('author', 'name'); if (!post) return res.status(404).json({m: "Post não encontrado."}); res.json(post);
    } catch (error) { console.error("[Foundry] Erro ao buscar post por ID (admin):", error); res.status(500).json({ m: "Erro ao buscar post." }); }
});
blogRouter.put('/:id', protectRoute, adminOnly, async (req, res) => { /* ... como no seu código original ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de post inválido."});
        const updateData = { ...req.body };
        if (updateData.slug) { 
            const newSlug = updateData.slug.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, ''); 
            const existingPostWithSlug = await BlogPost.findOne({ slug: newSlug, _id: { $ne: req.params.id } }); 
            if (existingPostWithSlug) return res.status(400).json({m: "Este slug já está em uso por outro post."}); 
            updateData.slug = newSlug;
        } else if (updateData.title && (req.body.slug === undefined || req.body.slug.trim() === '')) { // Gera slug se título mudou E slug não foi fornecido ou está vazio
            updateData.slug = updateData.title.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '');
        }
        if (updateData.content && updateData.snippet === undefined) { updateData.snippet = updateData.content.substring(0, 250) + (updateData.content.length > 250 ? '...' : ''); }
        updateData.updatedAt = Date.now();
        const updatedPost = await BlogPost.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true, runValidators: true });
        if (!updatedPost) return res.status(404).json({m: "Post não encontrado para atualização."});
        res.json({ m: "Post do blog atualizado com sucesso!", post: updatedPost });
    } catch (error) { console.error("[Foundry] Erro ao atualizar post do blog:", error); if (error.code === 11000) return res.status(400).json({m: "Um post com este título ou slug já existe."}); if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)}); res.status(500).json({ m: "Erro no servidor ao atualizar post." }); }
});
blogRouter.delete('/:id', protectRoute, adminOnly, async (req, res) => { /* ... como no seu código original ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de post inválido."});
        const deletedPost = await BlogPost.findByIdAndDelete(req.params.id);
        if (!deletedPost) return res.status(404).json({m: "Post não encontrado para deleção."});
        res.json({ m: "Post do blog deletado com sucesso." });
    } catch (error) { console.error("[Foundry] Erro ao deletar post do blog:", error); res.status(500).json({ m: "Erro no servidor ao deletar post." }); }
});
app.use('/api/blog', blogRouter);

const promotionRouter = express.Router();
promotionRouter.post('/', protectRoute, adminOnly, async (req, res) => { /* ... como no seu código original ... */ 
    try {
        const { title, description } = req.body; if (!title || !description) return res.status(400).json({m: "Título e descrição são obrigatórios para a promoção."});
        const newPromotionData = { ...req.body, isActive: req.body.isActive === true, startDate: req.body.startDate ? new Date(req.body.startDate) : Date.now(), endDate: req.body.endDate ? new Date(req.body.endDate) : null, countdownTargetDate: req.body.countdownTargetDate ? new Date(req.body.countdownTargetDate) : null };
        const newPromotion = new Promotion(newPromotionData); await newPromotion.save();
        res.status(201).json({ m: "Promoção criada com sucesso!", promotion: newPromotion });
    } catch (error) { console.error("[Foundry] Erro ao criar promoção:", error); if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)}); res.status(500).json({ m: "Erro no servidor ao criar promoção." }); }
});
promotionRouter.get('/active', async (req, res) => { /* ... como no seu código original ... */ 
    try {
        const now = new Date();
        const activePromotions = await Promotion.find({ isActive: true, $or: [ { startDate: { $lte: now } }, { startDate: null } ], $or: [ { endDate: { $gte: now } }, { endDate: null } ] }).sort({ priority: -1, createdAt: -1 }); 
        res.json(activePromotions);
    } catch (error) { console.error("[Foundry] Erro ao buscar promoções ativas:", error); res.status(500).json({ m: "Erro ao buscar promoções ativas." }); }
});
promotionRouter.get('/type/:typeName', async (req, res) => { /* ... como no seu código original ... */ 
    try { 
      const typeName = req.params.typeName.toLowerCase(); const now = new Date();
      console.log(`[Foundry][PROMO] Buscando promoções ativas do tipo: ${typeName}`); 
      const activePromotionsByType = await Promotion.find({ type: typeName, isActive: true, $or: [ { startDate: { $lte: now } }, { startDate: null } ], $or: [ { endDate: { $gte: now } }, { endDate: null } ] }).sort({ priority: -1, createdAt: -1 });
      if (!activePromotionsByType || activePromotionsByType.length === 0) {  console.log(`[Foundry][PROMO] Nenhuma promoção encontrada para ${typeName}.`); return res.status(200).json([]);  }
      console.log(`[Foundry][PROMO] Encontradas ${activePromotionsByType.length} promoções tipo ${typeName}.`); 
      res.json(activePromotionsByType);
    } catch (error) { console.error(`[Foundry][PROMO] Erro ao buscar promoções por tipo (${req.params.typeName}):`, error); res.status(500).json({ m: "Erro ao buscar promoções por tipo." }); }
});
promotionRouter.get('/all', protectRoute, adminOnly, async (req, res) => { /* ... como no seu código original ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 10; const skip = (page - 1) * limit;
        const isActiveFilter = req.query.isActive; let query = {}; if (isActiveFilter !== undefined) { query.isActive = (isActiveFilter === 'true'); }
        const promotions = await Promotion.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit);
        const totalPromotions = await Promotion.countDocuments(query);
        res.json({ promotions: promotions, currentPage: page, totalPages: Math.ceil(totalPromotions / limit), totalCount: totalPromotions });
    } catch (error) { console.error("[Foundry] Erro ao buscar todas promoções (admin):", error); res.status(500).json({ m: "Erro ao buscar promoções." }); }
});
promotionRouter.get('/:id', protectRoute, adminOnly, async (req, res) => { /* ... como no seu código original ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de promoção inválido."});
        const promotion = await Promotion.findById(req.params.id); if (!promotion) return res.status(404).json({m: "Promoção não encontrada."}); res.json(promotion);
    } catch (error) { console.error("[Foundry] Erro ao buscar promoção por ID (admin):", error); res.status(500).json({ m: "Erro ao buscar promoção." }); }
});
promotionRouter.put('/:id', protectRoute, adminOnly, async (req, res) => { /* ... como no seu código original ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de promoção inválido."});
        const updateData = { ...req.body };
        if (updateData.isActive !== undefined) { updateData.isActive = (updateData.isActive === true || updateData.isActive === 'true'); }
        if (updateData.startDate) updateData.startDate = new Date(updateData.startDate);
        if (updateData.endDate) updateData.endDate = new Date(updateData.endDate); else if (updateData.endDate === '') updateData.endDate = null; 
        if (updateData.countdownTargetDate) updateData.countdownTargetDate = new Date(updateData.countdownTargetDate); else if (updateData.countdownTargetDate === '') updateData.countdownTargetDate = null;
        const updatedPromotion = await Promotion.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true, runValidators: true });
        if (!updatedPromotion) return res.status(404).json({m: "Promoção não encontrada para atualização."});
        res.json({ m: "Promoção atualizada com sucesso!", promotion: updatedPromotion });
    } catch (error) { console.error("[Foundry] Erro ao atualizar promoção:", error); if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)}); res.status(500).json({ m: "Erro no servidor ao atualizar promoção." }); }
});
promotionRouter.delete('/:id', protectRoute, adminOnly, async (req, res) => { /* ... como no seu código original ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de promoção inválido."});
        const deletedPromotion = await Promotion.findByIdAndDelete(req.params.id);
        if (!deletedPromotion) return res.status(404).json({m: "Promoção não encontrada para deleção."});
        res.json({ m: "Promoção deletada com sucesso." });
    } catch (error) { console.error("[Foundry] Erro ao deletar promoção:", error); res.status(500).json({ m: "Erro no servidor ao deletar promoção." }); }
});
app.use('/api/promotions', promotionRouter);

// --- ROTAS DE COUNTDOWNS ---
const countdownRouter = express.Router(); 
// Admin: Criar contador
countdownRouter.post('/', protectRoute, adminOnly, async (req, res) => { 
    try { 
        const { title, description, targetDate, isActive, actionLink, displayLocation } = req.body; 
        if (!title || !targetDate) { return res.status(400).json({ m: "Título e Data Alvo são obrigatórios para o contador." }); } 
        const newCountdown = new Countdown({ title, description, targetDate: new Date(targetDate), isActive, actionLink, displayLocation }); 
        await newCountdown.save(); 
        res.status(201).json({ m: "Contador regressivo criado com sucesso!", countdown: newCountdown }); 
    } catch (error) { console.error("[Foundry] Erro ao criar countdown (admin):", error); if (error.name === 'ValidationError') return res.status(400).json({m: "Dados inválidos.", e: Object.values(error.errors).map(v=>v.message)}); res.status(500).json({ m: "Erro no servidor ao criar contador." }); } 
});
// Admin: Listar todos os contadores
countdownRouter.get('/all', protectRoute, adminOnly, async (req, res) => { 
    try { const countdowns = await Countdown.find().sort({ targetDate: -1 }); res.json(countdowns); 
    } catch (error) { console.error("[Foundry] Erro ao listar countdowns (admin):", error); res.status(500).json({ m: "Erro ao buscar contadores." }); } 
});
// Admin: Atualizar contador
countdownRouter.put('/:id', protectRoute, adminOnly, async (req, res) => { 
    try { 
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de contador inválido."}); 
        const updateData = { ...req.body }; 
        if (updateData.targetDate) updateData.targetDate = new Date(updateData.targetDate); 
        if (updateData.isActive !== undefined) updateData.isActive = (updateData.isActive === true || String(updateData.isActive).toLowerCase() === 'true'); 
        const updatedCountdown = await Countdown.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true, runValidators: true }); 
        if (!updatedCountdown) return res.status(404).json({m: "Contador não encontrado para atualização."}); 
        res.json({ m: "Contador atualizado com sucesso!", countdown: updatedCountdown }); 
    } catch (error) { console.error("[Foundry] Erro ao atualizar countdown (admin):", error); if (error.name === 'ValidationError') return res.status(400).json({m: "Dados inválidos.", e: Object.values(error.errors).map(v=>v.message)}); res.status(500).json({ m: "Erro no servidor ao atualizar contador." }); } 
});
// Admin: Deletar contador
countdownRouter.delete('/:id', protectRoute, adminOnly, async (req, res) => { 
    try { 
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de contador inválido."}); 
        const deletedCountdown = await Countdown.findByIdAndDelete(req.params.id); 
        if (!deletedCountdown) return res.status(404).json({m: "Contador não encontrado para deleção."}); 
        res.json({ m: "Contador deletado com sucesso." }); 
    } catch (error) { console.error("[Foundry] Erro ao deletar countdown (admin):", error); res.status(500).json({ m: "Erro no servidor ao deletar contador." }); } 
});
// Público: Listar contadores ativos
countdownRouter.get('/active', async (req, res) => {
    try { 
        const now = new Date(); 
        const activeCountdowns = await Countdown.find({ 
            isActive: true, 
            targetDate: { $gte: now }  
        }).sort({ targetDate: 1 });  
        console.log(`[Foundry][COUNTDOWN] Encontrados ${activeCountdowns.length} contadores ativos.`); 
        res.json(activeCountdowns); 
    } catch (error) { 
        console.error("[Foundry][COUNTDOWN] Erro ao buscar contadores ativos (público):", error); 
        res.status(500).json({ m: "Erro ao buscar contadores ativos." }); 
    }
});
app.use('/api/countdowns', countdownRouter); 
app.use('/api/admin/countdowns', countdownRouter); // As rotas de admin já estão protegidas dentro do router


// --- ROTAS DE INVESTIMENTOS DO USUÁRIO (/api/investments) COM CORREÇÃO PARA endDate ---
const investmentRouter = express.Router();
investmentRouter.use(protectRoute); // Aplica a proteção a todas as rotas de investimento

investmentRouter.post('/', async (req, res) => {
    console.log("[Foundry][INVEST] Rota POST /api/investments acessada");
    try {
        const { planId } = req.body;
        console.log(`[Foundry][INVEST] Tentando investir no planId: ${planId}`);
        if (!planId || !mongoose.Types.ObjectId.isValid(planId)) {
            console.warn("[Foundry][INVEST] ID do plano inválido recebido:", planId);
            return res.status(400).json({m:"ID do plano inválido."});
        }
        
        console.log("[Foundry][INVEST] Buscando plano...");
        const plan = await Plan.findOne({ _id: planId, isActive: true });
        if (!plan) {
            console.warn(`[Foundry][INVEST] Plano não encontrado ou inativo para planId: ${planId}`);
            return res.status(404).json({m:"Plano não encontrado ou está inativo."});
        }
        console.log("[Foundry][INVEST] Plano encontrado:", plan.name);
        
        console.log("[Foundry][INVEST] Buscando usuário:", req.user.id);
        const user = await User.findById(req.user.id);
        if (!user) {
            console.error("[Foundry][INVEST] Usuário não encontrado no banco de dados, mas token era válido. ID:", req.user.id);
            return res.status(404).json({m:"Usuário não encontrado."}); 
        }
        console.log(`[Foundry][INVEST] Usuário ${user.name} encontrado. Saldo: ${user.balance}`);
        if (user.balance < plan.price_mt) {
            console.warn(`[Foundry][INVEST] Saldo insuficiente para usuário ${user.name}. Saldo: ${user.balance}, Preço do Plano: ${plan.price_mt}`);
            return res.status(400).json({m:"Saldo insuficiente para adquirir este plano."});
        }

        if (plan.maxInvestmentsPerUser > 0) {
            console.log(`[Foundry][INVEST] Verificando maxInvestmentsPerUser (${plan.maxInvestmentsPerUser}) para o plano.`);
            const existingInvestmentsCount = await UserInvestment.countDocuments({ user: user._id, plan: plan._id });
            console.log(`[Foundry][INVEST] Usuário tem ${existingInvestmentsCount} investimentos neste plano.`);
            if (existingInvestmentsCount >= plan.maxInvestmentsPerUser) {
                return res.status(400).json({m: `Você já atingiu o limite de ${plan.maxInvestmentsPerUser} aquisição(ões) para este plano.`});
            }
        }

        const balanceBefore = user.balance;
        user.balance -= plan.price_mt;
        console.log(`[Foundry][INVEST] Saldo do usuário ${user.name} atualizado para: ${user.balance}`);
        
        // **CORREÇÃO PRINCIPAL: Definir startDate e endDate explicitamente AQUI**
        const startDate = new Date();
        const endDate = new Date(startDate.getTime() + plan.duration_days * 24 * 60 * 60 * 1000);
        
        // Calcula a próxima data de coleta também aqui, para consistência com o hook
        let firstCollection = new Date(startDate);
        firstCollection.setUTCDate(firstCollection.getUTCDate() + 1); 
        firstCollection.setUTCHours(PROFIT_COLLECTION_START_HOUR - TIMEZONE_OFFSET_HOURS, 0, 0, 0); 

        const newInvestment = new UserInvestment({
            user: user._id,
            plan: plan._id,
            planSnapshot: { 
                name: plan.name,
                price_mt: plan.price_mt,
                daily_profit_mt: plan.daily_profit_mt,
                duration_days: plan.duration_days
            },
            startDate: startDate,                 // Definido explicitamente
            endDate: endDate,                     // Definido explicitamente
            lastProfitCalculationTime: startDate, // Inicia cálculo de lucro a partir do início
            nextCollectionAvailableAt: firstCollection // Define a primeira data de coleta
        });
        console.log("[Foundry][INVEST] Objeto UserInvestment preparado:", newInvestment);
        console.log("[Foundry][INVEST] Tentando salvar UserInvestment...");
        
        await newInvestment.save(); // Agora o endDate está garantido e não dependerá apenas do hook
        console.log("[Foundry][INVEST] UserInvestment salvo com ID:", newInvestment._id);

        console.log("[Foundry][INVEST] Criando transação de compra de plano...");
        await createTransactionEntry(user._id, 'plan_purchase', -plan.price_mt, 
            `Compra do Plano: ${plan.name}`, 'completed', balanceBefore, user.balance, 
            {relatedInvestment: newInvestment._id});
        console.log("[Foundry][INVEST] Transação de compra criada.");

        // Lógica de Bônus de Indicação
        if (user.referredBy) {
            console.log(`[Foundry][INVEST] Usuário ${user.name} foi indicado por ${user.referredBy}. Verificando bônus de indicação.`);
            const referrer = await User.findById(user.referredBy);
            const systemSettings = await getOrInitializeSystemSettings();
            if (referrer && systemSettings.isReferralSystemActive && systemSettings.referralPlanPurchaseBonusPercentage > 0) {
                const bonusAmount = plan.price_mt * systemSettings.referralPlanPurchaseBonusPercentage;
                if (bonusAmount > 0) {
                    console.log(`[Foundry][INVEST] Calculando bônus de ${bonusAmount.toFixed(2)} MT para referente ${referrer.name}.`);
                    const referrerBalanceBefore = referrer.balance;
                    referrer.balance += bonusAmount;
                    console.log(`[Foundry][INVEST] Saldo do referente ${referrer.name} atualizado para ${referrer.balance}. Salvando referente...`);
                    await referrer.save();
                    console.log("[Foundry][INVEST] Referente salvo. Criando transação de bônus...");
                    await createTransactionEntry(referrer._id, 'referral_bonus_plan', bonusAmount, 
                        `Bônus por indicação (compra de plano por ${user.name})`, 'completed', 
                        referrerBalanceBefore, referrer.balance, {relatedUser: user._id});
                    console.log("[Foundry][INVEST] Transação de bônus criada. Enviando notificação ao referente...");
                    await createUserNotification(referrer._id, 'Você Ganhou um Bônus de Indicação!', 
                        `Você recebeu ${bonusAmount.toFixed(2)} MT porque ${user.name} adquiriu o plano ${plan.name}.`, 'success', '/referrals');
                }
            }
        }
        
        // ATUALIZADO: Define canWithdrawBonus como true após a primeira compra de plano
        const systemSettingsForBonusRule = await getOrInitializeSystemSettings();
        if (systemSettingsForBonusRule.bonusWithdrawalRequiresPlan && !user.canWithdrawBonus) {
             const totalUserInvestments = await UserInvestment.countDocuments({ user: user._id });
             if (totalUserInvestments === 1) { // Confirma que este é o primeiro investimento
                user.canWithdrawBonus = true;
                console.log(`[Foundry][INVEST] Usuário ${user.name} agora pode sacar bônus (canWithdrawBonus: true).`);
             }
        }

        console.log(`[Foundry][INVEST] Salvando usuário ${user.name} final...`);
        await user.save();
        console.log("[Foundry][INVEST] Usuário salvo. Enviando notificação de investimento...");
        await createUserNotification(user._id, 'Investimento Realizado com Sucesso!', 
            `Você investiu no plano ${plan.name}. Acompanhe seus lucros!`, 'success', '/investments/my-history');
        console.log("[Foundry][INVEST] Investimento concluído com sucesso.");
        res.status(201).json({ m: "Investimento realizado com sucesso!", investment: newInvestment });
    } catch (error) { 
        console.error("[Foundry][INVEST] ERRO CRÍTICO ao realizar investimento:", error.message, error.stack); 
        res.status(500).json({ m: "Erro no servidor ao tentar realizar o investimento. Por favor, contacte o suporte." });
    }
});
investmentRouter.get('/my-active', protectRoute, async (req, res) => { /* ... como no seu código original ... */ 
    try { await updateUncollectedProfits(req.user.id); 
        const activeInvestment = await UserInvestment.findOne({ user: req.user.id, isActive: true }).populate('plan', 'name icon_bs_class hashrate_mhs'); 
        if(!activeInvestment) return res.json(null); res.json(activeInvestment);
    } catch (error) { console.error("Erro ao buscar investimento ativo:", error); res.status(500).json({ m: "Erro ao buscar seu investimento ativo." }); }
});
investmentRouter.post('/collect-profit', protectRoute, async (req, res) => { /* ... como no seu código original ... */ 
    try {
        const userId = req.user.id; await updateUncollectedProfits(userId); 
        const investment = await UserInvestment.findOne({user: userId, isActive: true}); if (!investment) return res.status(404).json({m: "Nenhum investimento ativo encontrado para coletar lucros."});
        const now = new Date(); if (investment.nextCollectionAvailableAt && now < investment.nextCollectionAvailableAt) { const timeLeftMs = investment.nextCollectionAvailableAt.getTime() - now.getTime(); const hoursLeft = Math.floor(timeLeftMs / (1000 * 60 * 60)); const minutesLeft = Math.floor((timeLeftMs % (1000 * 60 * 60)) / (1000 * 60)); return res.status(400).json({m: `A próxima coleta de lucros estará disponível em aproximadamente ${hoursLeft}h ${minutesLeft}m.`}); }
        if (investment.uncollectedProfit <= 0) return res.status(400).json({m: "Não há lucros não coletados para este investimento."});
        const user = await User.findById(userId); if (!user) return res.status(404).json({m: "Usuário não encontrado."}); 
        const amountToCollect = parseFloat(investment.uncollectedProfit.toFixed(2)); const balanceBeforeCollection = user.balance; user.balance += amountToCollect;
        investment.totalProfitCollected += amountToCollect; investment.uncollectedProfit = 0; investment.lastCollectedAt = now; 
        let nextCollectionDateTimeLocal = new Date(now); nextCollectionDateTimeLocal.setHours(nextCollectionDateTimeLocal.getHours() + TIMEZONE_OFFSET_HOURS); nextCollectionDateTimeLocal.setDate(nextCollectionDateTimeLocal.getDate() + 1); nextCollectionDateTimeLocal.setHours(PROFIT_COLLECTION_START_HOUR, 0, 0, 0); 
        investment.nextCollectionAvailableAt = new Date(Date.UTC(nextCollectionDateTimeLocal.getUTCFullYear(), nextCollectionDateTimeLocal.getUTCMonth(), nextCollectionDateTimeLocal.getUTCDate(), nextCollectionDateTimeLocal.getUTCHours() - TIMEZONE_OFFSET_HOURS, 0,0,0));
        await createTransactionEntry(user._id, 'profit_collection', amountToCollect, `Coleta de lucros do plano: ${investment.planSnapshot.name}`, 'completed', balanceBeforeCollection, user.balance, {relatedInvestment: investment._id});
        if (user.referredBy) { const r=await User.findById(user.referredBy);const sS=await getOrInitializeSystemSettings();if(r&&sS.isReferralSystemActive&&sS.referralDailyProfitBonusPercentage>0){const dPB=parseFloat((amountToCollect*sS.referralDailyProfitBonusPercentage).toFixed(2));if(dPB>0){const rBB=r.balance;r.balance+=dPB;await r.save();await createTransactionEntry(r._id,'referral_bonus_profit',dPB,`Bônus por coleta de lucros de ${user.name}`,'completed',rBB,r.balance,{relatedUser:user._id});await createUserNotification(r._id,'Você Ganhou um Bônus de Indicação!',`Você recebeu ${dPB.toFixed(2)} MT porque ${user.name} coletou lucros.`,'success','/referrals');}}}
        await user.save(); await investment.save();
        await createUserNotification(user._id, 'Lucros Coletados com Sucesso!', `${amountToCollect.toFixed(2)} MT foram adicionados ao seu saldo. Saldo atual: ${user.balance.toFixed(2)} MT.`, 'success', '/wallet');
        res.json({ m: `${amountToCollect.toFixed(2)} MT coletados com sucesso!`, newBalance: user.balance.toFixed(2) });
    } catch(error) { console.error("Erro ao coletar lucros:", error); res.status(500).json({m:"Erro no servidor ao tentar coletar lucros."}); }
});
investmentRouter.get('/my-history', protectRoute, async (req, res) => { /* ... como no seu código original ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 10; const skip = (page - 1) * limit;
        const query = { user: req.user.id };
        const investments = await UserInvestment.find(query).populate('plan', 'name icon_bs_class').sort({ startDate: -1 }).skip(skip).limit(limit);
        const totalInvestments = await UserInvestment.countDocuments(query);
        res.json({ investments: investments, currentPage: page, totalPages: Math.ceil(totalInvestments / limit), totalCount: totalInvestments });
    } catch (error) { console.error("Erro ao buscar histórico de investimentos:", error); res.status(500).json({ m: "Erro ao buscar seu histórico de investimentos." }); }
});
app.use('/api/investments', investmentRouter);


// --- FUNÇÃO PRINCIPAL PARA INICIAR O SERVIDOR E CHAMADA FINAL ---
async function startServer() {
    if (!MONGO_URI) { console.error("FATAL: MONGO_URI não definida."); process.exit(1); }
    if (!JWT_SECRET) { console.error("FATAL: JWT_SECRET não definido."); process.exit(1); }
    try {
        await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        console.log('[Foundry] MongoDB Conectado!');
        
        await getOrInitializeSystemSettings(); 
        await createInitialAdmin(); 
        
        app.listen(PORT, () => {
            console.log(`[Foundry] Servidor Backend Foundry Invest rodando na Porta ${PORT}`);
            console.log('[Foundry] Todas as rotas e configurações carregadas. Backend pronto!');
        });
    } catch (error) {
        console.error('[Foundry] Falha Crítica ao Iniciar Servidor:', error.message, error.stack); 
        process.exit(1);
    }
}

if (require.main === module) { 
  startServer();
}

// module.exports = app; // Para testes