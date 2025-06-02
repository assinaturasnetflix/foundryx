// server.js
// Backend Foundry Invest Platform (Versão Consolidada e Corrigida com Funcionalidades Admin Expandidas)

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
const ADMIN_NAME = process.env.ADMIN_NAME || 'Admin Padrão Foundry';
const ADMIN_SECURITY_QUESTION = process.env.ADMIN_SECURITY_QUESTION;
const ADMIN_SECURITY_ANSWER_RAW = process.env.ADMIN_SECURITY_ANSWER_RAW;

const DEFAULT_REGISTRATION_BONUS = parseFloat(process.env.DEFAULT_REGISTRATION_BONUS) || 0;
const DEFAULT_REFERRAL_PLAN_BONUS_PERCENT = parseFloat(process.env.DEFAULT_REFERRAL_PLAN_BONUS_PERCENT) || 0.0;
const DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT = parseFloat(process.env.DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT) || 0.0;
const DEFAULT_MIN_WITHDRAWAL = parseFloat(process.env.DEFAULT_MIN_WITHDRAWAL) || 100; // Atualizado conforme solicitado
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
// UserSchema, SystemSettingsSchema, DepositMethodSchema, DepositRequestSchema, 
// WithdrawalRequestSchema, TransactionSchema, NotificationSchema, PlanSchema, 
// UserInvestmentSchema, BlogPostSchema, PromotionSchema
// (Todos os schemas como definidos anteriormente, sem alterações nesta etapa, exceto se explicitamente mencionado)

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
    canWithdrawBonus: { type: Boolean, default: false }, // Novo campo para controlar saque de bônus
    status: { type: String, enum: ['active', 'pending_verification', 'suspended', 'banned'], default: 'active'},
    lastLoginAt: { type: Date },
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
UserSchema.pre('save', async function(next) { /* ... como antes ... */ 
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
    bonusWithdrawalRequiresPlan: { type: Boolean, default: true }, // Configuração para saque de bônus
    lastUpdatedAt: { type: Date, default: Date.now }
});
SystemSettingsSchema.pre('save', function(next) { this.lastUpdatedAt = Date.now(); next(); });
const SystemSettings = mongoose.model('SystemSettings', SystemSettingsSchema);

// DepositMethodSchema, DepositRequestSchema, WithdrawalRequestSchema, TransactionSchema, NotificationSchema, PlanSchema, UserInvestmentSchema, BlogPostSchema, PromotionSchema
// ... (definições de schema como na última versão, PromotionSchema com 'blog' no enum type)
const DepositMethodSchema = new mongoose.Schema({ /* ... como antes ... */ 
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

const DepositRequestSchema = new mongoose.Schema({ /* ... como antes ... */ 
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

const WithdrawalRequestSchema = new mongoose.Schema({ /* ... como antes, com minWithdrawal a ser verificado contra SystemSettings ... */ 
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

const TransactionSchema = new mongoose.Schema({ /* ... como antes ... */ 
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { 
        type: String, 
        enum: [
            'deposit_approved', 'withdrawal_processed', 'plan_purchase', 'profit_collection', 
            'referral_bonus_plan', 'referral_bonus_profit', 'registration_bonus', 
            'admin_credit', 'admin_debit', 'withdrawal_fee', 'admin_plan_assignment', // Novo tipo
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

const NotificationSchema = new mongoose.Schema({ /* ... como antes ... */ 
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

const PlanSchema = new mongoose.Schema({ /* ... como antes ... */ 
    name: { type: String, required: true, trim: true, unique: true },
    price_mt: { type: Number, required: true, min: 1 },
    daily_profit_mt: { type: Number, required: true, min: 0.01 },
    duration_days: { type: Number, required: true, min: 1, default: 90 },
    hashrate_mhs: { type: Number, required: true, min: 0 }, 
    description: { type: String, trim: true, maxlength: 500, default: '' },
    icon_bs_class: { type: String, default: 'bi-gem' }, 
    isActive: { type: Boolean, default: true, index: true }, // Adicionado index para buscas mais rápidas
    features: [String], 
    maxInvestmentsPerUser: { type: Number, default: 1, min: 0 }, // 0 para ilimitado
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
PlanSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
const Plan = mongoose.model('Plan', PlanSchema);

const UserInvestmentSchema = new mongoose.Schema({ /* ... como antes ... */ 
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
    planSnapshot: { 
        name: {type: String, required: true},
        price_mt: {type: Number, required: true},
        daily_profit_mt: {type: Number, required: true},
        duration_days: {type: Number, required: true}
    },
    startDate: { type: Date, default: Date.now, index: true },
    endDate: { type: Date, required: true },
    isActive: { type: Boolean, default: true, index: true }, 
    totalProfitCollected: { type: Number, default: 0, min: 0 },
    uncollectedProfit: { type: Number, default: 0, min: 0 }, 
    lastProfitCalculationTime: { type: Date, default: Date.now }, 
    nextCollectionAvailableAt: { type: Date }, 
    lastCollectedAt: {type: Date }, // Novo campo para registrar a última coleta
    createdAt: { type: Date, default: Date.now }
});
UserInvestmentSchema.pre('save', function(next) { /* ... como antes ... */ 
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

const BlogPostSchema = new mongoose.Schema({ /* ... como antes ... */ 
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

const PromotionSchema = new mongoose.Schema({ /* ... como antes, com 'blog' type ... */ 
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true, trim: true },
    imageUrl: { type: String, trim: true, default: '' },
    linkUrl: { type: String, trim: true, default: '' }, 
    isActive: { type: Boolean, default: true, index: true },
    startDate: { type: Date, default: Date.now },
    endDate: { type: Date, default: null }, 
    countdownTargetDate: { type: Date, default: null }, 
    type: {type: String, enum: ['banner', 'popup', 'general', 'blog'], default: 'general'}, 
    priority: {type: Number, default: 0}, 
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
PromotionSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
const Promotion = mongoose.model('Promotion', PromotionSchema);

// -----------------------------------------------------------------------------
// --- FUNÇÕES AUXILIARES E MIDDLEWARES (protectRoute, adminOnly, etc.) ---
// -----------------------------------------------------------------------------
// ... (Funções auxiliares como protectRoute, adminOnly, getOrInitializeSystemSettings, createInitialAdmin, 
//      createTransactionEntry, createUserNotification, updateUncollectedProfits como definidas anteriormente)
const protectRoute = (req, res, next) => { /* ... como antes ... */ 
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
        console.error("Erro na verificação do token:", err);
        return res.status(500).json({ message: 'Erro ao verificar token.' });
    }
};

const adminOnly = async (req, res, next) => { /* ... como antes ... */ 
    try {
        if (req.user && req.user.id) {
            const userFromDb = await User.findById(req.user.id).select('role status');
            if (userFromDb && userFromDb.role === 'admin' && userFromDb.status === 'active') { next(); }
            else { res.status(403).json({ message: 'Acesso negado. Apenas administradores podem realizar esta ação.' }); }
        } else { res.status(401).json({ message: 'Não autorizado.' }); }
    } catch(error) { console.error("Erro na verificação de admin:", error); res.status(500).json({ message: "Erro ao verificar permissões de administrador."}); }
};

async function getOrInitializeSystemSettings() { /* ... como antes, adicionando bonusWithdrawalRequiresPlan ... */ 
    try {
        let settings = await SystemSettings.findOne({ singletonId: 'main_settings' });
        if (!settings) {
            console.log('Nenhuma configuração do sistema encontrada, inicializando com padrões...');
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
                bonusWithdrawalRequiresPlan: true // Novo, default para true
            });
            await settings.save();
            console.log('Configurações do sistema inicializadas com sucesso.');
        }
        return settings;
    } catch (error) { console.error("Erro ao obter/inicializar configurações do sistema:", error.message); throw new Error("Falha ao carregar as configurações do sistema."); }
}

async function createInitialAdmin() { /* ... como antes ... */ 
    try {
        if (!ADMIN_EMAIL || !ADMIN_PASSWORD) { console.warn("Credenciais do administrador padrão não definidas no .env. Admin não será criado."); return; }
        const adminExists = await User.findOne({ email: ADMIN_EMAIL });
        if (!adminExists) {
            const adminUser = new User({
                name: ADMIN_NAME, email: ADMIN_EMAIL, password: ADMIN_PASSWORD, 
                securityQuestion: ADMIN_SECURITY_QUESTION || "Pergunta de Segurança Padrão?",
                securityAnswer: ADMIN_SECURITY_ANSWER_RAW || "RespostaPadrão123", 
                role: 'admin', isEligibleForRegistrationBonus: false, status: 'active'
            });
            await adminUser.save(); console.log('Usuário administrador inicial criado com sucesso!');
        }
    } catch (error) { console.error('Erro ao criar administrador inicial:', error.message); }
}

async function createTransactionEntry(userId, type, amount, description, status = 'completed', balanceBefore, balanceAfter, relatedDocs = {}) { /* ... como antes ... */ 
    try { await Transaction.create({ user: userId, type, amount, description, status, balanceBefore, balanceAfter, ...relatedDocs });
    } catch (error) { console.error(`Erro ao criar transação [${type}] para usuário ${userId}:`, error.message); }
}

async function createUserNotification(userId, title, message, type = 'info', link = null, iconClass = null) { /* ... como antes ... */ 
    try {
        const notificationData = { user: userId, title, message, type, link };
        if(iconClass) { notificationData.iconClass = iconClass; } 
        else {
            const defaultIcons = {'success':'bi-check-circle-fill', 'error':'bi-x-octagon-fill', 'warning':'bi-exclamation-triangle-fill', 'profit':'bi-graph-up-arrow', 'investment':'bi-piggy-bank-fill', 'deposit':'bi-box-arrow-in-down', 'withdrawal':'bi-box-arrow-up-right', 'referral':'bi-people-fill'};
            notificationData.iconClass = defaultIcons[type] || 'bi-info-circle-fill'; 
        }
        await Notification.create(notificationData);
    } catch (error) { console.error(`Erro ao criar notificação para usuário ${userId}:`, error.message); }
}

async function updateUncollectedProfits(userId) { /* ... como antes ... */ 
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
    if (totalNewlyAccruedProfit > 0) { await createUserNotification(userId, "Lucros Diários Calculados", `Um total de ${totalNewlyAccruedProfit.toFixed(2)} MT em lucros diários foram calculados e adicionados ao seu saldo não coletado.`, "profit", "/investments/my-active"); }
    return { message: "Lucros não coletados dos investimentos ativos foram atualizados." };
}


// -----------------------------------------------------------------------------
// --- ROTAS DA API ---
// -----------------------------------------------------------------------------
app.get('/api', (req, res) => res.json({ message: 'API Foundry Invest Funcionando!' }));

// --- Rotas de Autenticação (/api/auth) ---
// ... (authRouter como definido anteriormente)
const authRouter = express.Router();
authRouter.post('/register', async (req, res) => { /* ... como antes ... */ 
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
            if (!referredByUser) { console.warn(`Código de indicação "${referralCodeProvided}" fornecido mas não encontrado.`); }
        }
        const systemSettings = await getOrInitializeSystemSettings();
        let initialBalance = 0; let registrationBonusApplied = 0; let userIsEligibleForBonus = true;
        if (systemSettings.isRegistrationBonusActive && systemSettings.registrationBonusAmount > 0 && userIsEligibleForBonus) {
            initialBalance += systemSettings.registrationBonusAmount; registrationBonusApplied = systemSettings.registrationBonusAmount; userIsEligibleForBonus = false; 
        }
        const newUser = new User({ name, email: normalizedEmail, password, securityQuestion, securityAnswer, referredBy: referredByUser ? referredByUser._id : null, balance: initialBalance, isEligibleForRegistrationBonus: userIsEligibleForBonus });
        await newUser.save();
        if (registrationBonusApplied > 0) {
            await createTransactionEntry(newUser._id, 'registration_bonus', registrationBonusApplied, 'Bônus de Registro', 'completed', 0, newUser.balance);
            await createUserNotification(newUser._id, 'Bem-vindo à Foundry Invest!', `Você recebeu um bônus de registro de ${registrationBonusApplied.toFixed(2)} MT!`, 'success', '/wallet');
        }
        if (referredByUser) { await createUserNotification(referredByUser._id, 'Nova Indicação!', `${newUser.name} registrou-se usando seu código de indicação.`, 'info', '/referrals'); }
        res.status(201).json({ m: 'Usuário registrado com sucesso!', userId: newUser._id });
    } catch (error) { console.error("Erro no registro de usuário:", error); if (error.name === 'ValidationError') { return res.status(400).json({ m: "Erro de validação nos dados fornecidos.", e: Object.values(error.errors).map(val => val.message) }); } res.status(500).json({ m: 'Ocorreu um erro no servidor ao tentar registrar o usuário.' }); }
});
authRouter.post('/login', async (req, res) => { /* ... como antes ... */ 
    try {
        const { email, password } = req.body; if (!email || !password) return res.status(400).json({ m: 'Email e senha são obrigatórios.' });
        const user = await User.findOne({ email: email.toLowerCase() }); if (!user) return res.status(401).json({ m: 'Credenciais inválidas.' });
        if (user.status !== 'active') return res.status(403).json({ m: `Sua conta está ${user.status}. Contacte o suporte.` });
        const MAX_FAILED_ATTEMPTS = 5; const LOCK_TIME = 15 * 60 * 1000; 
        if (user.lockUntil && user.lockUntil > Date.now()) { return res.status(403).json({ m: `Conta bloqueada devido a múltiplas tentativas falhas. Tente novamente em ${Math.ceil((user.lockUntil - Date.now()) / 60000)} minutos.` }); }
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            user.failedLoginAttempts += 1;
            if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) { user.lockUntil = Date.now() + LOCK_TIME; await createUserNotification(user._id, "Conta Temporariamente Bloqueada", "Sua conta foi bloqueada por 15 minutos devido a múltiplas tentativas de login malsucedidas.", 'error'); }
            await user.save(); return res.status(401).json({ m: 'Credenciais inválidas.' });
        }
        user.failedLoginAttempts = 0; user.lockUntil = undefined; user.lastLoginAt = Date.now(); await user.save();
        const payload = { user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        res.json({ m: "Login bem-sucedido!", token: token, user: payload.user });
    } catch (error) { console.error("Erro no login:", error); res.status(500).json({ m: 'Erro no servidor durante o login.' }); }
});
authRouter.post('/recover/request-question', async (req, res) => { /* ... como antes ... */ 
    try {
        const { email } = req.body; if (!email) return res.status(400).json({ m: "O endereço de email é obrigatório." });
        const user = await User.findOne({ email: email.toLowerCase() }).select('securityQuestion email'); 
        if (!user) return res.status(404).json({ m: "Endereço de email não encontrado em nosso sistema." });
        res.json({ email: user.email, securityQuestion: user.securityQuestion });
    } catch (error) { console.error("Erro ao solicitar pergunta de segurança:", error); res.status(500).json({ m: "Erro no servidor." }); }
});
authRouter.post('/recover/verify-answer', async (req, res) => { /* ... como antes ... */ 
    try {
        const { email, securityAnswer } = req.body; if (!email || !securityAnswer) return res.status(400).json({ m: "Email e resposta de segurança são obrigatórios." });
        const user = await User.findOne({ email: email.toLowerCase() }); if (!user) return res.status(404).json({ m: "Endereço de email não encontrado." });
        const isAnswerMatch = await user.compareSecurityAnswer(securityAnswer); if (!isAnswerMatch) return res.status(401).json({ m: "Resposta de segurança incorreta." });
        const resetToken = user.createPasswordResetToken(); await user.save({ validateBeforeSave: false }); 
        console.log(`Token de recuperação de senha para ${user.email} (uso em desenvolvimento): ${resetToken}`);
        res.json({ m: "Resposta verificada com sucesso. Um token de redefinição foi gerado e tem validade de 15 minutos.", resetTokenForFormSubmission: resetToken });
    } catch (error) { console.error("Erro ao verificar resposta de segurança:", error); res.status(500).json({ m: "Erro no servidor." }); }
});
authRouter.post('/recover/reset-password', async (req, res) => { /* ... como antes ... */ 
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
    } catch (error) { console.error("Erro ao redefinir senha:", error); res.status(500).json({ m: "Erro no servidor." }); }
});
app.use('/api/auth', authRouter);

// --- Rotas de Perfil do Usuário (/api/users) ---
// ... (userRouter como definido anteriormente, sem alterações de funcionalidade aqui)
const userRouter = express.Router();
userRouter.use(protectRoute); 
userRouter.get('/profile', async (req, res) => { /* ... como antes ... */ 
    try { const user = await User.findById(req.user.id).select('-password -securityQuestion -securityAnswer -passwordResetToken -passwordResetExpires -failedLoginAttempts -lockUntil -__v'); if (!user) return res.status(404).json({ m: "Usuário não encontrado." }); res.json(user);
    } catch (error) { console.error("Erro ao buscar perfil do usuário:", error); res.status(500).json({ m: "Erro ao buscar informações do perfil." }); }
});
userRouter.put('/profile', async (req, res) => { /* ... como antes ... */ 
    try {
        const { name } = req.body; const updateData = {};
        if (name && name.trim().length >= 3) { updateData.name = name.trim(); } else if (name) { return res.status(400).json({ m: "O nome deve ter pelo menos 3 caracteres." }); }
        if (Object.keys(updateData).length === 0) { return res.status(400).json({ m: "Nenhum dado válido fornecido para atualização." }); }
        const updatedUser = await User.findByIdAndUpdate(req.user.id, updateData, { new: true, runValidators: true }).select('-password -securityQuestion -securityAnswer -__v');
        if (!updatedUser) return res.status(404).json({ m: "Usuário não encontrado." });
        res.json({ m: "Perfil atualizado com sucesso.", user: updatedUser });
    } catch (error) { console.error("Erro ao atualizar perfil:", error); if (error.name === 'ValidationError') { return res.status(400).json({ m: "Dados inválidos.", e: Object.values(error.errors).map(val => val.message) }); } res.status(500).json({ m: "Erro ao atualizar perfil." }); }
});
userRouter.put('/change-password', async (req, res) => { /* ... como antes ... */ 
    try {
        const { currentPassword, newPassword, confirmNewPassword } = req.body;
        if (!currentPassword || !newPassword || !confirmNewPassword) { return res.status(400).json({ m: "Todos os campos de senha são obrigatórios." }); }
        if (newPassword.length < 6) return res.status(400).json({m:"Nova senha deve ter no mínimo 6 caracteres."});
        if (newPassword !== confirmNewPassword) return res.status(400).json({ m: "As novas senhas não coincidem." });
        const user = await User.findById(req.user.id); if (!user) return res.status(404).json({ m: "Usuário não encontrado." });
        const isMatch = await user.comparePassword(currentPassword); if (!isMatch) return res.status(401).json({ m: "Senha atual incorreta." });
        if (await bcrypt.compare(newPassword, user.password)) { return res.status(400).json({m: "A nova senha não pode ser igual à senha atual."}); }
        user.password = newPassword; await user.save();
        await createUserNotification(user._id,"Senha Alterada com Sucesso","Sua senha foi alterada. Por segurança, recomendamos que anote sua nova senha em local seguro.",'success');
        res.json({ m: "Senha alterada com sucesso." });
    } catch (error) { console.error("Erro ao alterar senha:", error); res.status(500).json({ m: "Erro ao alterar senha." }); }
});
userRouter.get('/referral-details', async (req, res) => { /* ... como antes ... */ 
    try {
        const user = await User.findById(req.user.id).select('referralCode'); if (!user) return res.status(404).json({ m: "Usuário não encontrado." });
        const totalReferredUsers = await User.countDocuments({ referredBy: req.user.id });
        const referralBonusesResult = await Transaction.aggregate([ { $match: { user: new mongoose.Types.ObjectId(req.user.id), type: { $in: ['referral_bonus_plan', 'referral_bonus_profit'] } } }, { $group: { _id: null, total: { $sum: '$amount' } } } ]);
        const totalReferralBonusEarned = referralBonusesResult.length > 0 ? referralBonusesResult[0].total.toFixed(2) : "0.00";
        res.json({ rC: user.referralCode, tRU: totalReferredUsers, tRBE: totalReferralBonusEarned });
    } catch (error) { console.error("Erro ao buscar detalhes de indicação:", error); res.status(500).json({ m: "Erro ao buscar detalhes de indicação." }); }
});
userRouter.get('/transactions', async (req, res) => { /* ... como antes ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 15; const skip = (page - 1) * limit;
        const transactionTypeFilter = req.query.type; let query = { user: req.user.id }; if (transactionTypeFilter) { query.type = transactionTypeFilter; }
        const transactions = await Transaction.find(query).sort({ transactionDate: -1 }).skip(skip).limit(limit);
        const totalTransactions = await Transaction.countDocuments(query);
        res.json({ transactions: transactions, currentPage: page, totalPages: Math.ceil(totalTransactions / limit), totalCount: totalTransactions });
    } catch (error) { console.error("Erro ao buscar transações:", error); res.status(500).json({ m: "Erro ao buscar transações." }); }
});
userRouter.get('/notifications', async (req, res) => { /* ... como antes ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 10; const skip = (page - 1) * limit;
        const notifications = await Notification.find({ user: req.user.id }).sort({ createdAt: -1 }).skip(skip).limit(limit);
        const totalNotifications = await Notification.countDocuments({ user: req.user.id });
        const unreadCount = await Notification.countDocuments({ user: req.user.id, isRead: false });
        res.json({ notifications: notifications, currentPage: page, totalPages: Math.ceil(totalNotifications / limit), totalCount: totalNotifications, unreadCount: unreadCount });
    } catch (error) { console.error("Erro ao buscar notificações:", error); res.status(500).json({ m: "Erro ao buscar notificações." }); }
});
userRouter.put('/notifications/:id/read', async (req, res) => { /* ... como antes ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de notificação inválido."});
        const notification = await Notification.findOneAndUpdate( { _id: req.params.id, user: req.user.id }, { isRead: true }, { new: true } );
        if (!notification) return res.status(404).json({ m: "Notificação não encontrada ou não pertence ao usuário." });
        res.json({ m: "Notificação marcada como lida.", notification: notification });
    } catch (error) { console.error("Erro ao marcar notificação como lida:", error); res.status(500).json({ m: "Erro ao atualizar notificação." }); }
});
userRouter.put('/notifications/read-all', async (req, res) => { /* ... como antes ... */ 
    try { await Notification.updateMany( { user: req.user.id, isRead: false }, { isRead: true } );
        res.json({ m: "Todas as notificações foram marcadas como lidas." });
    } catch (error) { console.error("Erro ao marcar todas as notificações como lidas:", error); res.status(500).json({ m: "Erro ao atualizar notificações." }); }
});
app.use('/api/users', userRouter);

// --- ROTAS DE ADMIN ---
const adminRouter = express.Router();
adminRouter.use(protectRoute, adminOnly); 

// --- ROTAS ADMIN: CRUD PARA PLANOS ---
// POST /api/admin/plans - Criar novo plano
adminRouter.post('/plans', async (req, res) => {
    try {
        const { name, price_mt, daily_profit_mt, duration_days, hashrate_mhs, description, icon_bs_class, isActive, features, maxInvestmentsPerUser } = req.body;
        if (!name || !price_mt || !daily_profit_mt || !duration_days || !hashrate_mhs) {
            return res.status(400).json({ m: "Campos obrigatórios para o plano (nome, preço, lucro diário, duração, hashrate) não fornecidos." });
        }
        const newPlan = new Plan({
            name, price_mt, daily_profit_mt, duration_days, hashrate_mhs, description,
            icon_bs_class: icon_bs_class || 'bi-gem',
            isActive: isActive !== undefined ? isActive : true,
            features: Array.isArray(features) ? features : (features ? features.split(',').map(f=>f.trim()) : []),
            maxInvestmentsPerUser: maxInvestmentsPerUser !== undefined ? parseInt(maxInvestmentsPerUser) : 1
        });
        await newPlan.save();
        res.status(201).json({ m: "Plano criado com sucesso!", plan: newPlan });
    } catch (error) {
        console.error("Erro ao criar plano (admin):", error);
        if (error.code === 11000) return res.status(400).json({m: "Um plano com este nome já existe."});
        if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)});
        res.status(500).json({ m: "Erro no servidor ao criar plano." });
    }
});

// GET /api/admin/plans/all - Listar todos os planos (ativos e inativos)
adminRouter.get('/plans/all', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const plans = await Plan.find({})
            .sort({ createdAt: -1 }) // Ou por preço, nome, etc.
            .skip(skip)
            .limit(limit);
        const totalPlans = await Plan.countDocuments({});
        res.json({ plans, currentPage: page, totalPages: Math.ceil(totalPlans / limit), totalCount: totalPlans });
    } catch (error) {
        console.error("Erro ao listar todos os planos (admin):", error);
        res.status(500).json({ m: "Erro ao listar planos." });
    }
});

// GET /api/admin/plans/:id - Ver detalhes de um plano específico
adminRouter.get('/plans/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ m: "ID de plano inválido." });
        const plan = await Plan.findById(req.params.id);
        if (!plan) return res.status(404).json({ m: "Plano não encontrado." });
        res.json(plan);
    } catch (error) {
        console.error("Erro ao buscar plano por ID (admin):", error);
        res.status(500).json({ m: "Erro ao buscar plano." });
    }
});

// PUT /api/admin/plans/:id - Atualizar um plano
adminRouter.put('/plans/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ m: "ID de plano inválido." });
        
        const updateData = { ...req.body };
        if (updateData.features && typeof updateData.features === 'string') {
            updateData.features = updateData.features.split(',').map(f => f.trim());
        }
        if (updateData.isActive !== undefined) {
            updateData.isActive = (updateData.isActive === true || updateData.isActive === 'true');
        }
        // Converte números para garantir tipo correto
        ['price_mt', 'daily_profit_mt', 'duration_days', 'hashrate_mhs', 'maxInvestmentsPerUser'].forEach(field => {
            if (updateData[field] !== undefined) updateData[field] = parseFloat(updateData[field]);
        });


        const updatedPlan = await Plan.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true, runValidators: true });
        if (!updatedPlan) return res.status(404).json({ m: "Plano não encontrado para atualização." });
        res.json({ m: "Plano atualizado com sucesso!", plan: updatedPlan });
    } catch (error) {
        console.error("Erro ao atualizar plano (admin):", error);
        if (error.code === 11000) return res.status(400).json({m: "Um plano com este nome já existe."});
        if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)});
        res.status(500).json({ m: "Erro no servidor ao atualizar plano." });
    }
});

// DELETE /api/admin/plans/:id - Desativar um plano (soft delete)
// Nota: Uma deleção real (`findByIdAndDelete`) pode ser perigosa se houver UserInvestments referenciando o plano.
// É mais seguro apenas desativá-lo. Se a deleção for necessária, adicione verificações.
adminRouter.delete('/plans/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ m: "ID de plano inválido." });
        
        // Verifica se há investimentos ativos com este plano antes de permitir desativação (ou deleção)
        const activeInvestments = await UserInvestment.countDocuments({ plan: req.params.id, isActive: true });
        if (activeInvestments > 0) {
            return res.status(400).json({m: `Não é possível desativar/deletar. Existem ${activeInvestments} investimentos ativos usando este plano.`});
        }

        // Para desativar:
        const plan = await Plan.findByIdAndUpdate(req.params.id, { isActive: false }, { new: true });
        if (!plan) return res.status(404).json({ m: "Plano não encontrado." });
        res.json({ m: "Plano desativado com sucesso.", plan });

        // Para deletar (use com cautela):
        /*
        const deletedPlan = await Plan.findByIdAndDelete(req.params.id);
        if (!deletedPlan) return res.status(404).json({ m: "Plano não encontrado para deleção." });
        res.json({ m: "Plano deletado com sucesso." });
        */
    } catch (error) {
        console.error("Erro ao desativar/deletar plano (admin):", error);
        res.status(500).json({ m: "Erro no servidor ao processar a requisição do plano." });
    }
});


// --- ROTA ADMIN: ATRIBUIR PLANO A USUÁRIO ---
adminRouter.post('/users/:userId/assign-plan', async (req, res) => {
    try {
        const { userId } = req.params;
        const { planId, adminNotes } = req.body;

        if (!mongoose.Types.ObjectId.isValid(userId)) return res.status(400).json({m: "ID de usuário inválido."});
        if (!planId || !mongoose.Types.ObjectId.isValid(planId)) return res.status(400).json({m:"ID do plano inválido."});

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({m: "Usuário não encontrado."});

        const plan = await Plan.findById(planId);
        if (!plan || !plan.isActive) return res.status(404).json({m: "Plano não encontrado ou inativo."});

        // Opcional: Verificar se o usuário já tem este plano ativo, se houver limites.
        // A lógica de maxInvestmentsPerUser é para compras do usuário, admin pode ter mais flexibilidade.
        // Para este caso, vamos assumir que o admin pode atribuir.

        const newInvestment = new UserInvestment({
            user: user._id,
            plan: plan._id,
            planSnapshot: {
                name: plan.name,
                price_mt: plan.price_mt, // Pode ser 0 se for uma atribuição gratuita
                daily_profit_mt: plan.daily_profit_mt,
                duration_days: plan.duration_days
            },
            // startDate é default: Date.now()
        });
        await newInvestment.save();

        // Criar uma transação para registrar esta atribuição administrativa.
        // O valor pode ser 0 se não houver custo, ou o preço do plano se for uma "compra" feita pelo admin.
        // Se for gratuito, o saldo do usuário não muda.
        const transactionDescription = `Plano "${plan.name}" atribuído pelo administrador. ${adminNotes ? 'Nota: ' + adminNotes : ''}`;
        await createTransactionEntry(
            user._id, 
            'admin_plan_assignment', // Novo tipo de transação
            0, // Assume custo 0 para atribuição admin. Se houver custo, use plan.price_mt (e ajuste o saldo do user)
            transactionDescription, 
            'completed', 
            user.balance, // Saldo antes (não muda se custo for 0)
            user.balance,   // Saldo depois (não muda se custo for 0)
            { relatedInvestment: newInvestment._id }
        );
        
        // Atualizar o campo canWithdrawBonus do usuário se este for o primeiro plano
        const userInvestmentCount = await UserInvestment.countDocuments({user: user._id});
        if (userInvestmentCount === 1 && !user.canWithdrawBonus) { // Se este é o primeiro plano
            user.canWithdrawBonus = true;
            await user.save();
        }


        await createUserNotification(user._id, 
            'Novo Plano Atribuído!', 
            `O plano "${plan.name}" foi atribuído à sua conta por um administrador.`, 
            'investment', 
            '/investments/my-active');

        res.status(201).json({m: `Plano "${plan.name}" atribuído com sucesso ao usuário ${user.name}.`, investment: newInvestment});

    } catch (error) {
        console.error("Erro ao atribuir plano ao usuário (admin):", error);
        res.status(500).json({m: "Erro no servidor ao atribuir plano."});
    }
});

// --- ROTA ADMIN: INICIAR RESET DE SENHA PARA USUÁRIO ---
adminRouter.post('/users/:userId/initiate-password-reset', async (req, res) => {
    try {
        const { userId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(userId)) return res.status(400).json({m: "ID de usuário inválido."});

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({m: "Usuário não encontrado."});

        const resetToken = user.createPasswordResetToken();
        await user.save({ validateBeforeSave: false });

        // Em um ambiente de produção, aqui você enviaria um email para user.email
        // contendo um link como `https://seusite.com/reset-password?token=${resetToken}`
        console.log(`ADMIN INITIATED RESET: Token de recuperação de senha para ${user.email} (uso em desenvolvimento): ${resetToken}`);
        
        await createUserNotification(user._id, 
            'Redefinição de Senha Iniciada', 
            'Um administrador iniciou um processo de redefinição de senha para sua conta. Por favor, verifique seu email (ou siga as instruções do administrador) para continuar.', 
            'warning'
        );

        res.json({m: `Processo de redefinição de senha iniciado para ${user.email}. O usuário precisa seguir as instruções (que seriam enviadas por email).`});

    } catch (error) {
        console.error("Erro ao iniciar reset de senha pelo admin:", error);
        res.status(500).json({m: "Erro no servidor ao iniciar reset de senha."});
    }
});


// Rotas de Admin existentes (settings, users, deposit-methods, etc.)
// ... (As rotas /api/admin/* que já existiam, como /settings, /users, etc., permanecem como antes)
adminRouter.get('/settings',async(req,res)=>{ /* ... como antes ... */ try{const s=await getOrInitializeSystemSettings();res.json(s);}catch(e){res.status(500).json({m:"Erro settings."})} });
adminRouter.put('/settings',async(req,res)=>{ /* ... como antes, com validação melhorada ... */ 
    try {
        const updates = req.body;
        const validNumberFields = ['registrationBonusAmount', 'referralPlanPurchaseBonusPercentage', 'referralDailyProfitBonusPercentage', 'minWithdrawalAmount', 'maxWithdrawalAmount', 'withdrawalFeePercentage', 'defaultPlanDuration'];
        const validBooleanFields = ['isReferralSystemActive', 'isRegistrationBonusActive', 'bonusWithdrawalRequiresPlan'];
        const settings = await SystemSettings.findOne({ singletonId: 'main_settings' });
        if (!settings) return res.status(404).json({ m: "Configurações do sistema não encontradas." });
        for (const key in updates) {
            if (settings.hasOwnProperty(key) && key !== 'singletonId' && key !== '_id' && key !== '__v' && key !== 'lastUpdatedAt') {
                 if (validNumberFields.includes(key)) {
                    const numValue = parseFloat(updates[key]);
                    if (!isNaN(numValue) && numValue >= 0 && (key.includes('Percentage') ? numValue <= 1 : true) ) { settings[key] = numValue; } 
                    else { return res.status(400).json({m: `Valor inválido para ${key}.`});}
                } else if (validBooleanFields.includes(key)) { settings[key] = (updates[key] === true || updates[key] === 'true'); }
            }
        }
        settings.lastUpdatedAt = Date.now(); await settings.save();
        res.json({ m: "Configurações do sistema atualizadas!", settings: settings });
    } catch (error) { console.error("Erro ao atualizar configurações:", error); res.status(500).json({ m: "Erro ao atualizar configurações." }); }
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
    } catch (error) { console.error("Erro ao listar usuários (admin):", error); res.status(500).json({ m: "Erro ao listar usuários." }); }
});
adminRouter.get('/users/:id',async(req,res)=>{ /* ... como antes ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de usuário inválido."});
        const user = await User.findById(req.params.id).select('-password -securityAnswer').populate('referredBy', 'name email');
        if (!user) return res.status(404).json({ m: "Usuário não encontrado." });
        const investments = await UserInvestment.find({user: user._id}).populate('plan', 'name price_mt').sort({startDate: -1});
        const transactions = await Transaction.find({user: user._id}).sort({transactionDate: -1}).limit(20); 
        const withdrawalRequests = await WithdrawalRequest.find({user: user._id}).sort({requestedAt: -1}).limit(10);
        const depositRequests = await DepositRequest.find({user: user._id}).sort({requestedAt: -1}).limit(10);
        res.json({ user: user, investments, transactions, withdrawalRequests, depositRequests });
    } catch (error) { console.error("Erro ao buscar detalhes do usuário (admin):", error); res.status(500).json({ m: "Erro ao buscar detalhes do usuário." }); }
});
adminRouter.put('/users/:id/update-details',async(req,res)=>{ /* ... como antes ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de usuário inválido."});
        const { name, email, role, status, balanceAdjustment, adjustmentReason } = req.body;
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
        if (balanceAdjustment !== undefined && typeof balanceAdjustment === 'number' && balanceAdjustment !== 0) {
            if (!adjustmentReason || adjustmentReason.trim() === '') { return res.status(400).json({m: "A razão para o ajuste de saldo é obrigatória."}); }
            const oldBalance = user.balance; const newBalance = user.balance + balanceAdjustment;
            if (newBalance < 0) return res.status(400).json({m: "Ajuste resultaria em saldo negativo."});
            user.balance = newBalance;
            await createTransactionEntry(user._id, balanceAdjustment > 0 ? 'admin_credit' : 'admin_debit', balanceAdjustment, `Ajuste de Administrador: ${adjustmentReason}`, 'completed', oldBalance, newBalance);
            await createUserNotification(user._id, "Saldo Ajustado pelo Administrador", `Seu saldo foi ajustado em ${balanceAdjustment.toFixed(2)} MT. Razão: ${adjustmentReason}.`, 'info');
        }
        await user.save();
        const userToReturn = user.toObject(); delete userToReturn.password; delete userToReturn.securityAnswer;
        res.json({ m: "Detalhes do usuário atualizados.", user: userToReturn, emailChanged: emailChanged });
    } catch (error) { console.error("Erro ao atualizar detalhes do usuário (admin):", error); res.status(500).json({ m: "Erro ao atualizar detalhes do usuário." }); }
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
    } catch (error) { console.error("Erro ao alterar status do usuário (admin):", error); res.status(500).json({ m: "Erro ao alterar status do usuário." }); }
});
adminRouter.post('/deposit-methods',async(req,res)=>{ /* ... como antes ... */ 
    try {
        const { name, instructions, paymentInfo } = req.body;
        if (!name || !instructions || !paymentInfo ) return res.status(400).json({m: "Nome, instruções e informações de pagamento são obrigatórios."});
        const newMethod = new DepositMethod(req.body); await newMethod.save();
        res.status(201).json({ m: "Novo método de depósito adicionado.", method: newMethod });
    } catch (error) { if (error.code === 11000) return res.status(400).json({m: "Um método de depósito com este nome já existe."}); console.error("Erro ao adicionar método de depósito:", error); res.status(500).json({ m: "Erro ao adicionar método de depósito." }); }
});
adminRouter.get('/deposit-methods',async(req,res)=>{ /* ... como antes ... */ 
    try { const methods = await DepositMethod.find().sort({ name: 1 }); res.json(methods);
    } catch (error) { console.error("Erro ao listar métodos de depósito:", error); res.status(500).json({ m: "Erro ao listar métodos de depósito." }); }
});
adminRouter.put('/deposit-methods/:id',async(req,res)=>{ /* ... como antes ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de método inválido."});
        const updatedMethod = await DepositMethod.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!updatedMethod) return res.status(404).json({m: "Método de depósito não encontrado."});
        res.json({ m: "Método de depósito atualizado.", method: updatedMethod });
    } catch (error) { if (error.code === 11000) return res.status(400).json({m: "Um método de depósito com este nome já existe."}); console.error("Erro ao atualizar método de depósito:", error); res.status(500).json({ m: "Erro ao atualizar método de depósito." }); }
});
adminRouter.delete('/deposit-methods/:id',async(req,res)=>{ /* ... como antes ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de método inválido."});
        const deletedMethod = await DepositMethod.findByIdAndDelete(req.params.id);
        if (!deletedMethod) return res.status(404).json({m: "Método de depósito não encontrado."});
        res.json({ m: "Método de depósito removido." });
    } catch (error) { console.error("Erro ao remover método de depósito:", error); res.status(500).json({ m: "Erro ao remover método de depósito." }); }
});
adminRouter.get('/deposit-requests',async(req,res)=>{ /* ... como antes ... */ 
    try {
        const { status, page = 1, limit = 10 } = req.query; const query = status ? { status } : {};
        const requests = await DepositRequest.find(query).populate('user', 'name email').populate('depositMethod', 'name').sort({ requestedAt: -1 }).limit(parseInt(limit)).skip((parseInt(page) - 1) * parseInt(limit));
        const count = await DepositRequest.countDocuments(query);
        res.json({ requests: requests, totalPages: Math.ceil(count / limit), currentPage: parseInt(page) });
    } catch (error) { console.error("Erro ao buscar solicitações de depósito (admin):", error); res.status(500).json({ m: "Erro ao buscar solicitações de depósito." }); }
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
    } catch (error) { console.error("Erro ao processar solicitação de depósito (admin):", error); res.status(500).json({ m: "Erro ao processar solicitação." }); }
});
adminRouter.get('/withdrawal-requests',async(req,res)=>{ /* ... como antes ... */ 
    try {
        const { status, page = 1, limit = 10 } = req.query; const query = status ? { status } : {};
        const requests = await WithdrawalRequest.find(query).populate('user', 'name email balance').sort({ requestedAt: -1 }).limit(parseInt(limit)).skip((parseInt(page) - 1) * parseInt(limit));
        const count = await WithdrawalRequest.countDocuments(query);
        res.json({ requests: requests, totalPages: Math.ceil(count / limit), currentPage: parseInt(page) });
    } catch (error) { console.error("Erro ao buscar solicitações de saque (admin):", error); res.status(500).json({ m: "Erro ao buscar solicitações de saque." }); }
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
    } catch (error) { console.error("Erro ao processar solicitação de saque (admin):", error); res.status(500).json({ m: "Erro ao processar solicitação de saque." }); }
});
adminRouter.get('/investments', async (req, res) => { /* ... como antes ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 15; const skip = (page - 1) * limit;
        const { userId, planId, isActive, sort = '-startDate' } = req.query; 
        let query = {}; if (userId && mongoose.Types.ObjectId.isValid(userId)) query.user = userId; if (planId && mongoose.Types.ObjectId.isValid(planId)) query.plan = planId; if (isActive !== undefined) query.isActive = (isActive === 'true');
        const investments = await UserInvestment.find(query).populate('user', 'name email').populate('plan', 'name').sort(sort).skip(skip).limit(limit);
        const totalInvestments = await UserInvestment.countDocuments(query);
        res.json({ investments: investments, currentPage: page, totalPages: Math.ceil(totalInvestments / limit), totalCount: totalInvestments });
    } catch (error) { console.error("Erro ao listar investimentos (admin):", error); res.status(500).json({ m: "Erro ao listar investimentos." }); }
});
adminRouter.get('/investments/:id', async (req, res) => { /* ... como antes ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de investimento inválido."});
        const investment = await UserInvestment.findById(req.params.id).populate('user', 'name email balance').populate('plan'); 
        if (!investment) return res.status(404).json({m: "Investimento não encontrado."}); res.json(investment);
    } catch (error) { console.error("Erro ao buscar detalhe do investimento (admin):", error); res.status(500).json({ m: "Erro ao buscar detalhe do investimento." }); }
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
    } catch (error) { console.error("Erro ao atualizar status do investimento (admin):", error); res.status(500).json({ m: "Erro ao atualizar status do investimento." }); }
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
    } catch(error) { console.error("Erro ao buscar estatísticas gerais:", error); res.status(500).json({m:"Erro ao buscar estatísticas."}); }
});
adminRouter.get('/stats/user-growth', async(req,res)=>{ /* ... como antes ... */ 
    try{
        const days = parseInt(req.query.days) || 30; const today = new Date(); today.setUTCHours(0,0,0,0); 
        const dateLimit = new Date(today); dateLimit.setDate(today.getDate() - days);
        const userGrowth = await User.aggregate([ {$match:{ createdAt: {$gte: dateLimit} }}, {$group:{ _id: { $dateToString:{format:"%Y-%m-%d", date:"$createdAt", timezone: "Africa/Maputo"} }, count: {$sum:1} }}, {$sort:{_id:1}} ]);
        res.json(userGrowth);
    }catch(error){ console.error("Erro ao buscar estatísticas de crescimento de usuários:", error); res.status(500).json({m:"Erro ao buscar estatísticas de crescimento."}); }
});
app.use('/api/admin', adminRouter);

// --- Rotas Públicas (Planos, Métodos de Depósito, Blog público, Promoções públicas) ---
// ... (publicPlanRouter, publicDepositMethodRouter, blogRouter (rotas públicas), promotionRouter (rota pública /active) como antes)
const publicPlanRouter = express.Router();
publicPlanRouter.get('/', async (req, res) => { /* ... como antes ... */ 
    try { const plans = await Plan.find({ isActive: true }).sort({ price_mt: 1 }); res.json(plans);
    } catch (error) { console.error("Erro ao buscar planos públicos:", error); res.status(500).json({ m: "Erro ao buscar planos." }); }
});
publicPlanRouter.get('/:id', async (req, res) => { /* ... como antes ... */ 
    try { if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de plano inválido."});
        const plan = await Plan.findById(req.params.id); if (!plan || !plan.isActive) return res.status(404).json({ m: "Plano não encontrado ou inativo." }); res.json(plan);
    } catch (error) { console.error("Erro ao buscar plano público por ID:", error); res.status(500).json({ m: "Erro ao buscar plano." }); }
});
app.use('/api/plans', publicPlanRouter);

const publicDepositMethodRouter = express.Router();
publicDepositMethodRouter.get('/', async (req, res) => { /* ... como antes ... */ 
    try { const methods = await DepositMethod.find({ isActive: true }).select('-createdAt -updatedAt -__v -accountDetailsSchema'); res.json(methods);
    } catch (error) { console.error("Erro ao buscar métodos de depósito públicos:", error); res.status(500).json({ m: "Erro ao buscar métodos de depósito." }); }
});
app.use('/api/deposit-methods', publicDepositMethodRouter); 

const blogRouter = express.Router();
blogRouter.post('/', protectRoute, adminOnly, async (req, res) => { /* ... como antes ... */ 
    try {
        const { title, content, slug, snippet, tags, isPublished, coverImageUrl } = req.body;
        if (!title || !content) return res.status(400).json({m: "Título e conteúdo são obrigatórios para o post."});
        let postSlug = slug; if (!postSlug) { postSlug = title.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, ''); }
        const existingSlug = await BlogPost.findOne({ slug: postSlug }); if (existingSlug) return res.status(400).json({m: "Este slug já está em uso. Escolha outro."});
        const newPost = new BlogPost({ title, content, slug: postSlug, snippet: snippet || (content.length > 250 ? content.substring(0, 250) + '...' : content), tags: tags || [], isPublished: isPublished === true, coverImageUrl, author: req.user.id });
        await newPost.save(); res.status(201).json({ m: "Post do blog criado com sucesso!", post: newPost });
    } catch (error) { console.error("Erro ao criar post do blog:", error); if (error.code === 11000) return res.status(400).json({m: "Um post com este título ou slug já existe."}); if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)}); res.status(500).json({ m: "Erro no servidor ao criar post." }); }
});
blogRouter.get('/', async (req, res) => { /* ... como antes (rota pública) ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 10; const skip = (page - 1) * limit;
        const tagFilter = req.query.tag; const searchQuery = req.query.search;
        let query = { isPublished: true }; if (tagFilter) query.tags = tagFilter.trim().toLowerCase(); if (searchQuery) query.title = { $regex: searchQuery, $options: 'i' }; 
        const posts = await BlogPost.find(query).populate('author', 'name').sort({ createdAt: -1 }).skip(skip).limit(limit).select('title slug snippet tags createdAt coverImageUrl author views'); 
        const totalPosts = await BlogPost.countDocuments(query);
        res.json({ posts: posts, currentPage: page, totalPages: Math.ceil(totalPosts / limit), totalCount: totalPosts });
    } catch (error) { console.error("Erro ao buscar posts do blog (público):", error); res.status(500).json({ m: "Erro ao buscar posts do blog." }); }
});
blogRouter.get('/all', protectRoute, adminOnly, async (req, res) => { /* ... como antes (rota admin) ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 20; const skip = (page - 1) * limit;
        const { isPublished, search } = req.query; let query = {};
        if (isPublished !== undefined) query.isPublished = (isPublished === 'true'); if (search) query.title = { $regex: search, $options: 'i' };
        const posts = await BlogPost.find(query).populate('author', 'name').sort({ createdAt: -1 }).skip(skip).limit(limit);
        const totalPosts = await BlogPost.countDocuments(query);
        res.json({ posts: posts, currentPage: page, totalPages: Math.ceil(totalPosts / limit), totalCount: totalPosts });
    } catch (error) { console.error("Erro ao buscar todos os posts (admin):", error); res.status(500).json({ m: "Erro ao buscar posts." }); }
});
blogRouter.get('/slug/:slug', async (req, res) => { /* ... como antes (rota pública) ... */ 
    try {
        const post = await BlogPost.findOneAndUpdate( { slug: req.params.slug.toLowerCase(), isPublished: true }, { $inc: { views: 1 } }, { new: true } ).populate('author', 'name');
        if (!post) return res.status(404).json({ m: "Post do blog não encontrado ou não publicado." }); res.json(post);
    } catch (error) { console.error("Erro ao buscar post do blog por slug:", error); res.status(500).json({ m: "Erro ao buscar post." }); }
});
blogRouter.get('/id/:id', protectRoute, adminOnly, async (req, res) => { /* ... como antes (rota admin) ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de post inválido."});
        const post = await BlogPost.findById(req.params.id).populate('author', 'name'); if (!post) return res.status(404).json({m: "Post não encontrado."}); res.json(post);
    } catch (error) { console.error("Erro ao buscar post por ID (admin):", error); res.status(500).json({ m: "Erro ao buscar post." }); }
});
blogRouter.put('/:id', protectRoute, adminOnly, async (req, res) => { /* ... como antes ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de post inválido."});
        const updateData = { ...req.body };
        if (updateData.slug) { const newSlug = updateData.slug.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, ''); const existingPostWithSlug = await BlogPost.findOne({ slug: newSlug, _id: { $ne: req.params.id } }); if (existingPostWithSlug) return res.status(400).json({m: "Este slug já está em uso por outro post."}); updateData.slug = newSlug;
        } else if (updateData.title && !updateData.slug) { updateData.slug = updateData.title.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, ''); }
        if (updateData.content && updateData.snippet === undefined) { updateData.snippet = updateData.content.substring(0, 250) + (updateData.content.length > 250 ? '...' : ''); }
        updateData.updatedAt = Date.now();
        const updatedPost = await BlogPost.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true, runValidators: true });
        if (!updatedPost) return res.status(404).json({m: "Post não encontrado para atualização."});
        res.json({ m: "Post do blog atualizado com sucesso!", post: updatedPost });
    } catch (error) { console.error("Erro ao atualizar post do blog:", error); if (error.code === 11000) return res.status(400).json({m: "Um post com este título ou slug já existe."}); if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)}); res.status(500).json({ m: "Erro no servidor ao atualizar post." }); }
});
blogRouter.delete('/:id', protectRoute, adminOnly, async (req, res) => { /* ... como antes ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de post inválido."});
        const deletedPost = await BlogPost.findByIdAndDelete(req.params.id);
        if (!deletedPost) return res.status(404).json({m: "Post não encontrado para deleção."});
        res.json({ m: "Post do blog deletado com sucesso." });
    } catch (error) { console.error("Erro ao deletar post do blog:", error); res.status(500).json({ m: "Erro no servidor ao deletar post." }); }
});
app.use('/api/blog', blogRouter); // Monta as rotas de blog (públicas e admin)

// --- ROTAS DE PROMOÇÕES (/api/promotions) ---
const promotionRouter = express.Router();
promotionRouter.post('/', protectRoute, adminOnly, async (req, res) => { /* ... como antes ... */ 
    try {
        const { title, description } = req.body; if (!title || !description) return res.status(400).json({m: "Título e descrição são obrigatórios para a promoção."});
        const newPromotionData = { ...req.body, isActive: req.body.isActive === true, startDate: req.body.startDate ? new Date(req.body.startDate) : Date.now(), endDate: req.body.endDate ? new Date(req.body.endDate) : null, countdownTargetDate: req.body.countdownTargetDate ? new Date(req.body.countdownTargetDate) : null };
        const newPromotion = new Promotion(newPromotionData); await newPromotion.save();
        res.status(201).json({ m: "Promoção criada com sucesso!", promotion: newPromotion });
    } catch (error) { console.error("Erro ao criar promoção:", error); if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)}); res.status(500).json({ m: "Erro no servidor ao criar promoção." }); }
});
promotionRouter.get('/active', async (req, res) => { /* ... como antes ... */ 
    try {
        const now = new Date();
        const activePromotions = await Promotion.find({ isActive: true, $or: [ { startDate: { $lte: now } }, { startDate: null } ], $or: [ { endDate: { $gte: now } }, { endDate: null } ] }).sort({ priority: -1, createdAt: -1 }); 
        res.json(activePromotions);
    } catch (error) { console.error("Erro ao buscar promoções ativas:", error); res.status(500).json({ m: "Erro ao buscar promoções ativas." }); }
});
promotionRouter.get('/type/:typeName', async (req, res) => { /* ... como antes ... */ 
    try {
      const typeName = req.params.typeName.toLowerCase(); const now = new Date();
      const activePromotionsByType = await Promotion.find({ type: typeName, isActive: true, $or: [ { startDate: { $lte: now } }, { startDate: null } ], $or: [ { endDate: { $gte: now } }, { endDate: null } ] }).sort({ priority: -1, createdAt: -1 });
      if (!activePromotionsByType || activePromotionsByType.length === 0) { return res.status(200).json([]); }
      res.json(activePromotionsByType);
    } catch (error) { console.error(`Erro ao buscar promoções ativas por tipo (${req.params.typeName}):`, error); res.status(500).json({ m: "Erro ao buscar promoções por tipo." }); }
});
promotionRouter.get('/all', protectRoute, adminOnly, async (req, res) => { /* ... como antes ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 10; const skip = (page - 1) * limit;
        const isActiveFilter = req.query.isActive; let query = {}; if (isActiveFilter !== undefined) { query.isActive = (isActiveFilter === 'true'); }
        const promotions = await Promotion.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit);
        const totalPromotions = await Promotion.countDocuments(query);
        res.json({ promotions: promotions, currentPage: page, totalPages: Math.ceil(totalPromotions / limit), totalCount: totalPromotions });
    } catch (error) { console.error("Erro ao buscar todas as promoções (admin):", error); res.status(500).json({ m: "Erro ao buscar promoções." }); }
});
promotionRouter.get('/:id', protectRoute, adminOnly, async (req, res) => { /* ... como antes ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de promoção inválido."});
        const promotion = await Promotion.findById(req.params.id); if (!promotion) return res.status(404).json({m: "Promoção não encontrada."}); res.json(promotion);
    } catch (error) { console.error("Erro ao buscar promoção por ID (admin):", error); res.status(500).json({ m: "Erro ao buscar promoção." }); }
});
promotionRouter.put('/:id', protectRoute, adminOnly, async (req, res) => { /* ... como antes ... */ 
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
    } catch (error) { console.error("Erro ao atualizar promoção:", error); if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)}); res.status(500).json({ m: "Erro no servidor ao atualizar promoção." }); }
});
promotionRouter.delete('/:id', protectRoute, adminOnly, async (req, res) => { /* ... como antes ... */ 
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de promoção inválido."});
        const deletedPromotion = await Promotion.findByIdAndDelete(req.params.id);
        if (!deletedPromotion) return res.status(404).json({m: "Promoção não encontrada para deleção."});
        res.json({ m: "Promoção deletada com sucesso." });
    } catch (error) { console.error("Erro ao deletar promoção:", error); res.status(500).json({ m: "Erro no servidor ao deletar promoção." }); }
});
app.use('/api/promotions', promotionRouter);


// --- Rotas de Solicitação de Depósito e Saque do Usuário ---
// ... (depositUserRouter, withdrawalUserRouter como definidos anteriormente)
const depositUserRouter = express.Router();
depositUserRouter.post('/request', async (req, res) => { /* ... como antes ... */ 
    try {
        const { amount, depositMethodId, userTransactionReference } = req.body;
        if (!amount || !depositMethodId || !userTransactionReference) { return res.status(400).json({m: "Valor, método de depósito e referência da transação são obrigatórios."}); }
        if(!mongoose.Types.ObjectId.isValid(depositMethodId)) return res.status(400).json({m:"ID do método de depósito inválido."});
        const method = await DepositMethod.findById(depositMethodId); if (!method || !method.isActive) return res.status(404).json({m: "Método de depósito não encontrado ou inativo."});
        const parsedAmount = parseFloat(amount);
        if (isNaN(parsedAmount) || parsedAmount < method.minAmount || parsedAmount > method.maxAmount) { return res.status(400).json({m: `O valor do depósito deve estar entre ${method.minAmount} e ${method.maxAmount} ${method.currency}.`}); }
        const newRequest = new DepositRequest({ user: req.user.id, amount: parsedAmount, depositMethod: depositMethodId, userTransactionReference: userTransactionReference.trim() });
        await newRequest.save();
        await createUserNotification(req.user.id, "Solicitação de Depósito Recebida", `Sua solicitação de depósito de ${newRequest.amount.toFixed(2)} ${newRequest.currency} foi recebida e está em processamento.`, 'info', '/transactions');
        res.status(201).json({ m: "Solicitação de depósito recebida com sucesso. Aguarde o processamento.", request: newRequest });
    } catch (error) { console.error("Erro ao criar solicitação de depósito:", error); res.status(500).json({ m: "Erro ao processar sua solicitação de depósito." }); }
});
app.use('/api/deposits', protectRoute, depositUserRouter);

const withdrawalUserRouter = express.Router();
withdrawalUserRouter.post('/request', async (req, res) => { /* ... como antes, com a verificação de bônus ... */ 
    try {
        const { amount, withdrawalMethodType, withdrawalAccountDetails } = req.body;
        if (!amount || !withdrawalMethodType || !withdrawalAccountDetails || typeof withdrawalAccountDetails !== 'object' || Object.keys(withdrawalAccountDetails).length === 0) { return res.status(400).json({m: "Valor, tipo de método de saque e detalhes da conta de saque são obrigatórios."}); }
        const parsedAmount = parseFloat(amount); if (isNaN(parsedAmount) || parsedAmount <= 0) return res.status(400).json({m: "Valor de saque inválido."});
        
        const systemSettings = await getOrInitializeSystemSettings();
        if (parsedAmount < systemSettings.minWithdrawalAmount || parsedAmount > systemSettings.maxWithdrawalAmount) { return res.status(400).json({m: `O valor do saque deve estar entre ${systemSettings.minWithdrawalAmount} e ${systemSettings.maxWithdrawalAmount} MT.`}); }

        const user = await User.findById(req.user.id); if (!user) return res.status(404).json({m: "Usuário não encontrado."});

        // Verifica se o usuário pode sacar bônus
        if (systemSettings.bonusWithdrawalRequiresPlan && !user.canWithdrawBonus) {
            // Esta lógica precisa ser mais refinada. O `user.balance` inclui bônus?
            // Se sim, precisaríamos de um campo `bonusBalance` e `withdrawableBalance`.
            // Por agora, uma regra simples: se `canWithdrawBonus` é false, e o admin configurou que precisa de plano, barramos.
            // Isso não impede saque de SALDO REAL, apenas de um saldo que *fosse apenas bônus*.
            // A forma mais correta seria separar `bonusBalance` de `realBalance`.
            // Como não temos isso, essa verificação é mais um aviso.
            // A lógica real de "o que é bônus" vs "o que é saldo depositado/lucro" está no tipo de transação.
            // Aqui, vamos simplificar e assumir que o usuário é avisado pelo frontend e o admin controla.
            // No futuro, o `canWithdrawBonus` seria setado para true após a primeira compra de plano efetiva.
            const totalInvestments = await UserInvestment.countDocuments({user: user._id});
            if(totalInvestments === 0 && systemSettings.bonusWithdrawalRequiresPlan) {
                 // Se o saldo for igual ao bônus de registro e não tiver planos, pode ser um alerta
                 if (user.balance <= systemSettings.registrationBonusAmount && systemSettings.isRegistrationBonusActive){
                    return res.status(400).json({ m: "Você precisa ativar um plano de investimento antes de poder sacar o bônus de registro." });
                 }
            }
            // Se canWithdrawBonus for false (setado pelo admin ou por regra), podemos impedir ou avisar.
            // Por ora, a flag `user.canWithdrawBonus` pode ser usada pelo admin para controlar.
        }


        const feeCharged = parsedAmount * systemSettings.withdrawalFeePercentage;
        if (user.balance < parsedAmount) { return res.status(400).json({m: "Saldo insuficiente para cobrir o valor do saque."}); }
        
        const pendingWithdrawal = await WithdrawalRequest.findOne({ user: req.user.id, status: 'pending' });
        if (pendingWithdrawal) return res.status(400).json({m: "Você já possui uma solicitação de saque pendente. Aguarde o processamento."});

        const newRequest = new WithdrawalRequest({ user: req.user.id, amount: parsedAmount, withdrawalMethodType: withdrawalMethodType, withdrawalAccountDetails: withdrawalAccountDetails, feeCharged: feeCharged });
        await newRequest.save();
        await createUserNotification(user._id, "Solicitação de Saque Recebida", `Sua solicitação de saque de ${newRequest.amount.toFixed(2)} MT está em processamento. Taxa: ${feeCharged.toFixed(2)} MT. Líquido: ${newRequest.netAmount.toFixed(2)} MT.`, 'info', '/transactions');
        res.status(201).json({ m: "Solicitação de saque recebida com sucesso. Aguarde o processamento.", request: newRequest });
    } catch (error) { console.error("Erro ao criar solicitação de saque:", error); res.status(500).json({ m: "Erro ao processar sua solicitação de saque." }); }
});
app.use('/api/withdrawals', protectRoute, withdrawalUserRouter);


// --- ROTAS DE INVESTIMENTOS DO USUÁRIO (/api/investments) ---
// ... (investmentRouter como definido anteriormente)
const investmentRouter = express.Router(); 
investmentRouter.post('/', async (req, res) => { /* ... como antes, mas agora UserInvestmentSchema.pre('save') seta canWithdrawBonus=true ... */ 
    try {
        const { planId } = req.body; if (!planId || !mongoose.Types.ObjectId.isValid(planId)) return res.status(400).json({m:"ID do plano inválido."});
        const plan = await Plan.findOne({ _id: planId, isActive: true }); if (!plan) return res.status(404).json({m:"Plano não encontrado ou está inativo."});
        const user = await User.findById(req.user.id); if (!user) return res.status(404).json({m:"Usuário não encontrado."}); 
        if (user.balance < plan.price_mt) return res.status(400).json({m:"Saldo insuficiente para adquirir este plano."});
        if (plan.maxInvestmentsPerUser > 0) { const existingInvestmentsCount = await UserInvestment.countDocuments({ user: user._id, plan: plan._id }); if (existingInvestmentsCount >= plan.maxInvestmentsPerUser) { return res.status(400).json({m: `Você já atingiu o limite de ${plan.maxInvestmentsPerUser} aquisição(ões) para este plano.`}); } }
        const balanceBefore = user.balance; user.balance -= plan.price_mt;
        const newInvestment = new UserInvestment({ user: user._id, plan: plan._id, planSnapshot: { name: plan.name, price_mt: plan.price_mt, daily_profit_mt: plan.daily_profit_mt, duration_days: plan.duration_days } });
        await newInvestment.save(); 
        await createTransactionEntry(user._id, 'plan_purchase', -plan.price_mt, `Compra do Plano: ${plan.name}`, 'completed', balanceBefore, user.balance, {relatedInvestment: newInvestment._id});
        if (user.referredBy) { /* ... lógica de bônus de indicação ... */ }
        
        // MARCAR QUE O USUÁRIO AGORA PODE SACAR BÔNUS
        if (!user.canWithdrawBonus) {
            user.canWithdrawBonus = true;
        }
        await user.save(); 
        await createUserNotification(user._id, 'Investimento Realizado com Sucesso!', `Você investiu no plano ${plan.name}. Acompanhe seus lucros!`, 'success', '/investments/my-history');
        res.status(201).json({ m: "Investimento realizado com sucesso!", investment: newInvestment });
    } catch (error) { console.error("Erro ao realizar investimento:", error); res.status(500).json({ m: "Erro no servidor ao tentar realizar o investimento." }); }
});
investmentRouter.get('/my-active', async (req, res) => { /* ... como antes ... */ 
    try { await updateUncollectedProfits(req.user.id); 
        const activeInvestment = await UserInvestment.findOne({ user: req.user.id, isActive: true }).populate('plan', 'name icon_bs_class hashrate_mhs'); 
        if(!activeInvestment) return res.json(null); res.json(activeInvestment);
    } catch (error) { console.error("Erro ao buscar investimento ativo:", error); res.status(500).json({ m: "Erro ao buscar seu investimento ativo." }); }
});
investmentRouter.post('/collect-profit', async (req, res) => { /* ... como antes ... */ 
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
        if (user.referredBy) { /* ... lógica de bônus de indicação por coleta ... */ }
        await user.save(); await investment.save();
        await createUserNotification(user._id, 'Lucros Coletados com Sucesso!', `${amountToCollect.toFixed(2)} MT foram adicionados ao seu saldo. Saldo atual: ${user.balance.toFixed(2)} MT.`, 'success', '/wallet');
        res.json({ m: `${amountToCollect.toFixed(2)} MT coletados com sucesso!`, newBalance: user.balance.toFixed(2) });
    } catch(error) { console.error("Erro ao coletar lucros:", error); res.status(500).json({m:"Erro no servidor ao tentar coletar lucros."}); }
});
investmentRouter.get('/my-history', async (req, res) => { /* ... como antes ... */ 
    try {
        const page = parseInt(req.query.page) || 1; const limit = parseInt(req.query.limit) || 10; const skip = (page - 1) * limit;
        const query = { user: req.user.id };
        const investments = await UserInvestment.find(query).populate('plan', 'name icon_bs_class').sort({ startDate: -1 }).skip(skip).limit(limit);
        const totalInvestments = await UserInvestment.countDocuments(query);
        res.json({ investments: investments, currentPage: page, totalPages: Math.ceil(totalInvestments / limit), totalCount: totalInvestments });
    } catch (error) { console.error("Erro ao buscar histórico de investimentos:", error); res.status(500).json({ m: "Erro ao buscar seu histórico de investimentos." }); }
});
app.use('/api/investments', protectRoute, investmentRouter);


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
            console.log(`Servidor Backend Foundry Invest rodando na Porta ${PORT}`);
            console.log('Todas as rotas e configurações carregadas. Backend pronto!');
        });
    } catch (error) {
        console.error('Falha Crítica ao Iniciar Servidor:', error.message);
        process.exit(1);
    }
}

if (require.main === module) { 
  startServer();
}

