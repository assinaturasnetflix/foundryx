// server.js
// Backend Foundry Invest Platform (Versão Consolidada e Corrigida)

// --- Dependências ---
require('dotenv').config(); // Deve vir primeiro se outras configs dependem dele

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors'); // Importando o cors

// --- Constantes e Configurações Globais ---
const app = express();
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1d'; // 1 dia por padrão

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_NAME = process.env.ADMIN_NAME || 'Admin Padrão Foundry'; // Nome atualizado
const ADMIN_SECURITY_QUESTION = process.env.ADMIN_SECURITY_QUESTION;
const ADMIN_SECURITY_ANSWER_RAW = process.env.ADMIN_SECURITY_ANSWER_RAW;

const DEFAULT_REGISTRATION_BONUS = parseFloat(process.env.DEFAULT_REGISTRATION_BONUS) || 0;
const DEFAULT_REFERRAL_PLAN_BONUS_PERCENT = parseFloat(process.env.DEFAULT_REFERRAL_PLAN_BONUS_PERCENT) || 0.0;
const DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT = parseFloat(process.env.DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT) || 0.0;
const DEFAULT_MIN_WITHDRAWAL = parseFloat(process.env.DEFAULT_MIN_WITHDRAWAL) || 50;
const DEFAULT_MAX_WITHDRAWAL = parseFloat(process.env.DEFAULT_MAX_WITHDRAWAL) || 100000;
const DEFAULT_WITHDRAWAL_FEE_PERCENT = parseFloat(process.env.DEFAULT_WITHDRAWAL_FEE_PERCENT) || 0.01;

// Configurações de fuso horário para coleta de lucros
const TIMEZONE_OFFSET_HOURS = parseInt(process.env.TIMEZONE_OFFSET_HOURS) || 2; // Maputo GMT+2
const PROFIT_COLLECTION_START_HOUR = parseInt(process.env.PROFIT_COLLECTION_START_HOUR) || 8; // 8 AM Hora Local


if (!MONGO_URI || !JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD || !ADMIN_SECURITY_QUESTION || !ADMIN_SECURITY_ANSWER_RAW) {
    console.error("ERRO FATAL: Variáveis de ambiente críticas não definidas. Verifique seu arquivo .env");
    process.exit(1);
}

// --- Middlewares Globais ---
app.use(cors()); // Habilita o CORS para todas as origens. Deve vir antes das rotas.
app.use(express.json()); // Para parsear o corpo de requisições JSON

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
    referralCode: { type: String, unique: true, sparse: true, trim: true, uppercase: true }, // Usado no link de indicação
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
            const UserModel = mongoose.model('User'); // Garante que o modelo está disponível
            const existingUser = await UserModel.findOne({ referralCode: potentialCode });
            if (!existingUser) { this.referralCode = potentialCode; uniqueCode = true; }
            attempts++;
        }
        // Fallback se todas as tentativas falharem (extremamente raro com 4 bytes hex)
        if (!uniqueCode) { this.referralCode = `${crypto.randomBytes(3).toString('hex').toUpperCase()}${Date.now().toString().slice(-4)}`; }
    }
    next();
});
UserSchema.methods.comparePassword = async function(candidatePassword) { return bcrypt.compare(candidatePassword, this.password); };
UserSchema.methods.compareSecurityAnswer = async function(candidateAnswer) { return bcrypt.compare(candidateAnswer, this.securityAnswer); };
UserSchema.methods.createPasswordResetToken = function() {
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpires = Date.now() + 15 * 60 * 1000; // 15 minutos
    return resetToken;
};
const User = mongoose.model('User', UserSchema);

const SystemSettingsSchema = new mongoose.Schema({
    singletonId: { type: String, default: 'main_settings', unique: true, required: true },
    registrationBonusAmount: { type: Number, default: DEFAULT_REGISTRATION_BONUS, min: 0 },
    referralPlanPurchaseBonusPercentage: { type: Number, default: DEFAULT_REFERRAL_PLAN_BONUS_PERCENT, min: 0, max: 1 }, // ex: 0.05 para 5%
    referralDailyProfitBonusPercentage: { type: Number, default: DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT, min: 0, max: 1 }, // ex: 0.01 para 1%
    minWithdrawalAmount: { type: Number, default: DEFAULT_MIN_WITHDRAWAL, min: 0 },
    maxWithdrawalAmount: { type: Number, default: DEFAULT_MAX_WITHDRAWAL, min: 0 },
    withdrawalFeePercentage: {type: Number, default: DEFAULT_WITHDRAWAL_FEE_PERCENT, min:0, max:1},
    defaultPlanDuration: { type: Number, default: 90, min: 1}, // Duração padrão em dias
    isReferralSystemActive: { type: Boolean, default: true },
    isRegistrationBonusActive: { type: Boolean, default: true },
    lastUpdatedAt: { type: Date, default: Date.now }
});
SystemSettingsSchema.pre('save', function(next) { this.lastUpdatedAt = Date.now(); next(); });
const SystemSettings = mongoose.model('SystemSettings', SystemSettingsSchema);

const DepositMethodSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true, trim: true },
    instructions: { type: String, required: true, trim: true }, // Instruções gerais
    accountDetailsSchema: { type: mongoose.Schema.Types.Mixed }, // Campos específicos que o admin preenche (ex: { "Número da Conta": "123", "Nome do Banco": "ABC"})
    paymentInfo: { type: mongoose.Schema.Types.Mixed, required: true }, // Campos que o usuário preenche (ex: { "Número de Transação": "string", "Nome do Depositante": "string" })
    minAmount: { type: Number, default: 50, min: 1 },
    maxAmount: { type: Number, default: 100000, min: 1 },
    feePercentage: {type: Number, default: 0, min: 0, max: 1},
    feeFixed: {type: Number, default: 0, min: 0},
    iconClass: { type: String, default: 'bi-credit-card' }, // Classe de ícone Bootstrap
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
    userTransactionReference: { type: String, required: [true, "A referência da transação é obrigatória."], trim: true }, // Ex: ID da transação M-Pesa
    userNotes: { type: String, trim: true, maxlength: 500 }, // Notas do usuário, se houver
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'cancelled_by_user'], default: 'pending', index: true },
    adminNotes: { type: String, trim: true, maxlength: 500 },
    rejectionReason: { type: String, trim: true, maxlength: 500 },
    requestedAt: { type: Date, default: Date.now },
    processedAt: { type: Date } // Data em que o admin processou (aprovou/rejeitou)
});
const DepositRequest = mongoose.model('DepositRequest', DepositRequestSchema);

const WithdrawalRequestSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    amount: { type: Number, required: [true, "O valor é obrigatório."], min: [1, "Valor mínimo de saque é 1."] }, // Valor bruto solicitado pelo usuário
    currency: { type: String, default: "MT", uppercase: true },
    withdrawalMethodType: { type: String, required: true }, // Ex: 'M-Pesa', 'Transferência Bancária'
    withdrawalAccountDetails: { type: mongoose.Schema.Types.Mixed, required: true }, // Ex: { "Número M-Pesa": "84XXXXXXX" }
    feeCharged: { type: Number, default: 0 }, // Taxa calculada
    netAmount: {type: Number }, // Valor líquido a ser pago (amount - feeCharged)
    status: { type: String, enum: ['pending', 'approved', 'processing', 'completed', 'rejected', 'failed', 'cancelled_by_user'], default: 'pending', index: true },
    adminNotes: { type: String, trim: true, maxlength: 500 },
    rejectionReason: {type: String, trim: true, maxlength: 500},
    transactionIdFromProvider: {type: String, trim: true}, // ID da transação do provedor de pagamento (ex: M-Pesa)
    requestedAt: { type: Date, default: Date.now },
    processedAt: { type: Date }, // Admin aprovou/rejeitou
    completedAt: { type: Date } // Dinheiro enviado/pagamento confirmado
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
    amount: { type: Number, required: true }, // Positivo para créditos, negativo para débitos
    currency: { type: String, default: 'MT', uppercase: true },
    description: { type: String, trim: true, required: true, maxlength: 255 },
    status: { type: String, enum: ['pending', 'completed', 'failed', 'reversed'], default: 'completed' },
    balanceBefore: { type: Number }, // Saldo do usuário antes da transação
    balanceAfter: { type: Number },  // Saldo do usuário após a transação
    relatedDepositRequest: { type: mongoose.Schema.Types.ObjectId, ref: 'DepositRequest', default: null },
    relatedWithdrawalRequest: { type: mongoose.Schema.Types.ObjectId, ref: 'WithdrawalRequest', default: null },
    relatedInvestment: { type: mongoose.Schema.Types.ObjectId, ref: 'UserInvestment', default: null },
    relatedUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // Para bônus de indicação, quem foi o indicado
    transactionDate: { type: Date, default: Date.now, index: true }
});
const Transaction = mongoose.model('Transaction', TransactionSchema);


const NotificationSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    title: { type: String, required: true, trim: true, maxlength: 100 },
    message: { type: String, required: true, trim: true, maxlength: 500 },
    type: { type: String, enum: ['info', 'success', 'warning', 'error', 'profit', 'investment', 'deposit', 'withdrawal', 'referral'], default: 'info' },
    isRead: { type: Boolean, default: false, index: true },
    link: { type: String, default: null, trim: true }, // Ex: '/transactions/ID_DA_TRANSACAO'
    iconClass: { type: String, default: 'bi-info-circle'}, // Classe de ícone Bootstrap
    createdAt: { type: Date, default: Date.now, index: true }
});
const Notification = mongoose.model('Notification', NotificationSchema);

const PlanSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, unique: true },
    price_mt: { type: Number, required: true, min: 1 },
    daily_profit_mt: { type: Number, required: true, min: 0.01 },
    duration_days: { type: Number, required: true, min: 1, default: 90 },
    hashrate_mhs: { type: Number, required: true, min: 0 }, // Ex: 100 MH/s
    description: { type: String, trim: true, maxlength: 500, default: '' },
    icon_bs_class: { type: String, default: 'bi-gem' }, // Ícone Bootstrap para o plano
    isActive: { type: Boolean, default: true },
    features: [String], // Lista de características, ex: ["Suporte Prioritário", "Retirada Rápida"]
    maxInvestmentsPerUser: { type: Number, default: 1 }, // Quantas vezes um usuário pode comprar este plano (1 = apenas uma vez)
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
PlanSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
const Plan = mongoose.model('Plan', PlanSchema);


const UserInvestmentSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
    planSnapshot: { // Guarda os detalhes do plano no momento da compra
        name: {type: String, required: true},
        price_mt: {type: Number, required: true},
        daily_profit_mt: {type: Number, required: true},
        duration_days: {type: Number, required: true}
        // Pode adicionar hashrate_mhs aqui se for relevante para o histórico
    },
    startDate: { type: Date, default: Date.now, index: true },
    endDate: { type: Date, required: true },
    isActive: { type: Boolean, default: true, index: true }, // Se o investimento está ativo e gerando lucro
    totalProfitCollected: { type: Number, default: 0, min: 0 },
    uncollectedProfit: { type: Number, default: 0, min: 0 }, // Lucro gerado mas ainda não coletado pelo usuário
    lastProfitCalculationTime: { type: Date, default: Date.now }, // Última vez que o lucro foi calculado para este investimento
    nextCollectionAvailableAt: { type: Date }, // Próxima data/hora que o usuário pode coletar o lucro
    createdAt: { type: Date, default: Date.now }
});
UserInvestmentSchema.pre('save', function(next) {
    if (this.isNew) {
        this.endDate = new Date(this.startDate.getTime() + this.planSnapshot.duration_days * 24 * 60 * 60 * 1000);
        
        // Define a próxima coleta para o dia seguinte à data de início, na hora configurada
        let firstCollection = new Date(this.startDate);
        firstCollection.setUTCDate(firstCollection.getUTCDate() + 1); // Dia seguinte UTC
        // Ajusta para o fuso horário local, depois para a hora de coleta, depois de volta para UTC para salvar
        firstCollection.setUTCHours(PROFIT_COLLECTION_START_HOUR - TIMEZONE_OFFSET_HOURS, 0, 0, 0); 
        this.nextCollectionAvailableAt = firstCollection;
        this.lastProfitCalculationTime = this.startDate; // Lucro começa a contar a partir da data de início
    }
    next();
});
const UserInvestment = mongoose.model('UserInvestment', UserInvestmentSchema);

const BlogPostSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true, unique:true },
    slug: { type: String, required: true, unique: true, lowercase: true, trim: true }, // Ex: meu-primeiro-post
    content: { type: String, required: true }, // Conteúdo HTML completo do post
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Admin que criou
    snippet: { type: String, trim: true, maxlength: 300 }, // Pequeno resumo
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
    linkUrl: { type: String, trim: true, default: '' }, // Link para onde a promoção/banner leva
    isActive: { type: Boolean, default: true, index: true },
    startDate: { type: Date, default: Date.now },
    endDate: { type: Date, default: null }, // Null significa sem data de fim
    countdownTargetDate: { type: Date, default: null }, // Para cronômetros
    type: {type: String, enum: ['banner', 'popup', 'general', 'blog'], default: 'general'}, // Adicionado 'blog'
    priority: {type: Number, default: 0}, // Para ordenar banners/promoções
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

    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7); // Remove "Bearer "
    }

    if (!token) {
        return res.status(401).json({ message: 'Acesso negado. Token não fornecido.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user; // Adiciona o payload do usuário (id, nome, email, role) ao objeto req
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expirado.' });
        }
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token inválido.' });
        }
        // Outros erros de JWT ou erros inesperados
        console.error("Erro na verificação do token:", err);
        return res.status(500).json({ message: 'Erro ao verificar token.' });
    }
};

const adminOnly = async (req, res, next) => {
    // Assumindo que protectRoute já foi chamado e req.user está populado
    try {
        if (req.user && req.user.id) {
            // Buscar o usuário do banco para garantir que o 'role' e 'status' são atuais
            const userFromDb = await User.findById(req.user.id).select('role status');
            if (userFromDb && userFromDb.role === 'admin' && userFromDb.status === 'active') {
                next();
            } else {
                res.status(403).json({ message: 'Acesso negado. Apenas administradores podem realizar esta ação.' });
            }
        } else {
            // Isso não deveria acontecer se protectRoute foi chamado antes
            res.status(401).json({ message: 'Não autorizado.' });
        }
    } catch(error) {
        console.error("Erro na verificação de admin:", error);
        res.status(500).json({ message: "Erro ao verificar permissões de administrador."});
    }
};

async function getOrInitializeSystemSettings() {
    try {
        let settings = await SystemSettings.findOne({ singletonId: 'main_settings' });
        if (!settings) {
            console.log('Nenhuma configuração do sistema encontrada, inicializando com padrões...');
            settings = new SystemSettings({
                // Os valores padrão já são definidos no Schema, mas podemos reforçar aqui se necessário
                registrationBonusAmount: DEFAULT_REGISTRATION_BONUS,
                referralPlanPurchaseBonusPercentage: DEFAULT_REFERRAL_PLAN_BONUS_PERCENT,
                referralDailyProfitBonusPercentage: DEFAULT_REFERRAL_DAILY_PROFIT_BONUS_PERCENT,
                minWithdrawalAmount: DEFAULT_MIN_WITHDRAWAL,
                maxWithdrawalAmount: DEFAULT_MAX_WITHDRAWAL,
                withdrawalFeePercentage: DEFAULT_WITHDRAWAL_FEE_PERCENT,
                defaultPlanDuration: parseInt(process.env.DEFAULT_PLAN_DURATION) || 90, // Exemplo, pode ser do .env
                isReferralSystemActive: process.env.IS_REFERRAL_SYSTEM_ACTIVE !== 'false', // Default true se não especificado ou true
                isRegistrationBonusActive: process.env.IS_REGISTRATION_BONUS_ACTIVE !== 'false' // Default true
            });
            await settings.save();
            console.log('Configurações do sistema inicializadas com sucesso.');
        }
        return settings;
    } catch (error) {
        console.error("Erro ao obter/inicializar configurações do sistema:", error.message);
        // Em um cenário de produção, talvez lançar um erro mais crítico ou ter um fallback
        throw new Error("Falha ao carregar as configurações do sistema.");
    }
}

async function createInitialAdmin() {
    try {
        if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
            console.warn("Credenciais do administrador padrão não definidas no .env. Admin não será criado.");
            return;
        }
        const adminExists = await User.findOne({ email: ADMIN_EMAIL });
        if (!adminExists) {
            const adminUser = new User({
                name: ADMIN_NAME,
                email: ADMIN_EMAIL,
                password: ADMIN_PASSWORD, // O hook pre-save fará o hash
                securityQuestion: ADMIN_SECURITY_QUESTION || "Pergunta de Segurança Padrão?",
                securityAnswer: ADMIN_SECURITY_ANSWER_RAW || "RespostaPadrão123", // O hook pre-save fará o hash
                role: 'admin',
                isEligibleForRegistrationBonus: false, // Admin não recebe bônus de registro
                status: 'active'
            });
            await adminUser.save();
            console.log('Usuário administrador inicial criado com sucesso!');
        }
    } catch (error) {
        console.error('Erro ao criar administrador inicial:', error.message);
    }
}

// Função para criar entrada de transação e notificação
async function createTransactionEntry(userId, type, amount, description, status = 'completed', balanceBefore, balanceAfter, relatedDocs = {}) {
    try {
        await Transaction.create({
            user: userId, type, amount, description, status, balanceBefore, balanceAfter, ...relatedDocs
        });
    } catch (error) {
        console.error(`Erro ao criar transação [${type}] para usuário ${userId}:`, error.message);
        // Considerar um sistema de log mais robusto ou retry em produção
    }
}

async function createUserNotification(userId, title, message, type = 'info', link = null, iconClass = null) {
    try {
        const notificationData = { user: userId, title, message, type, link };
        if(iconClass) {
            notificationData.iconClass = iconClass;
        } else {
            // Mapeamento de tipos para ícones padrão Bootstrap
            const defaultIcons = {
                'success': 'bi-check-circle-fill',
                'error': 'bi-x-octagon-fill',
                'warning': 'bi-exclamation-triangle-fill',
                'profit': 'bi-graph-up-arrow',
                'investment': 'bi-piggy-bank-fill',
                'deposit': 'bi-box-arrow-in-down', // Ícone para depósito
                'withdrawal': 'bi-box-arrow-up-right', // Ícone para saque
                'referral': 'bi-people-fill' // Ícone para indicação
            };
            notificationData.iconClass = defaultIcons[type] || 'bi-info-circle-fill'; // Default para 'info'
        }
        await Notification.create(notificationData);
    } catch (error) {
        console.error(`Erro ao criar notificação para usuário ${userId}:`, error.message);
    }
}

async function updateUncollectedProfits(userId) {
    const now = new Date();
    const userInvestments = await UserInvestment.find({ user: userId, isActive: true });
    let totalNewlyAccruedProfit = 0;

    for (const investment of userInvestments) {
        // Se o investimento já terminou, marca como inativo e pula
        if (now >= investment.endDate) {
            if (investment.isActive) {
                investment.isActive = false;
                await investment.save();
                await createUserNotification(investment.user, 
                    "Plano Concluído", 
                    `Seu plano de investimento "${investment.planSnapshot.name}" foi concluído.`, 
                    "info", 
                    "/investments/my-history"); // Link para histórico
            }
            continue;
        }
        // Se o investimento ainda não começou, pula
        if (now < investment.startDate) continue;

        let calculationReferenceTime = new Date(investment.lastProfitCalculationTime);
        
        // Normaliza para o início do dia no fuso horário da aplicação (considerando o offset)
        let startOfLastCalcDayLocal = new Date(calculationReferenceTime);
        startOfLastCalcDayLocal.setHours(startOfLastCalcDayLocal.getHours() + TIMEZONE_OFFSET_HOURS); // Ajusta para local
        startOfLastCalcDayLocal.setHours(0,0,0,0); // Zera hora local

        let startOfCurrentDayLocal = new Date(now);
        startOfCurrentDayLocal.setHours(startOfCurrentDayLocal.getHours() + TIMEZONE_OFFSET_HOURS); // Ajusta para local
        startOfCurrentDayLocal.setHours(0,0,0,0); // Zera hora local

        let daysPassedSinceLastCalc = 0;
        if (startOfCurrentDayLocal > startOfLastCalcDayLocal) {
            daysPassedSinceLastCalc = Math.floor((startOfCurrentDayLocal.getTime() - startOfLastCalcDayLocal.getTime()) / (1000 * 60 * 60 * 24));
        }

        if (daysPassedSinceLastCalc > 0) {
            const investmentEndDate = new Date(investment.endDate);
            // Quantos dias faltam para o fim do investimento a partir do último dia de cálculo (considerando o dia inteiro)
            const daysLeftInInvestment = Math.max(0, 
                Math.floor((investmentEndDate.getTime() - startOfLastCalcDayLocal.getTime()) / (1000 * 60 * 60 * 24))
            );

            const daysToCredit = Math.min(daysPassedSinceLastCalc, daysLeftInInvestment);

            if (daysToCredit > 0) {
                const profitToAdd = daysToCredit * investment.planSnapshot.daily_profit_mt;
                investment.uncollectedProfit = (investment.uncollectedProfit || 0) + profitToAdd;
                
                // Atualiza lastProfitCalculationTime para o início do último dia creditado (local), depois converte para UTC
                let newLastCalcTimeLocal = new Date(startOfLastCalcDayLocal);
                newLastCalcTimeLocal.setDate(newLastCalcTimeLocal.getDate() + daysToCredit);
                investment.lastProfitCalculationTime = new Date(Date.UTC(
                    newLastCalcTimeLocal.getFullYear(), 
                    newLastCalcTimeLocal.getMonth(), 
                    newLastCalcTimeLocal.getDate(),
                    0 - TIMEZONE_OFFSET_HOURS, // Volta para UTC
                    0,0,0
                ));
                
                totalNewlyAccruedProfit += profitToAdd;
                await investment.save();
            }
        }
    }
    if (totalNewlyAccruedProfit > 0) {
        await createUserNotification(userId, 
            "Lucros Diários Calculados", 
            `Um total de ${totalNewlyAccruedProfit.toFixed(2)} MT em lucros diários foram calculados e adicionados ao seu saldo não coletado.`, 
            "profit", 
            "/investments/my-active");
    }
    return { message: "Lucros não coletados dos investimentos ativos foram atualizados." };
}


// -----------------------------------------------------------------------------
// --- ROTAS DA API ---
// -----------------------------------------------------------------------------
app.get('/api', (req, res) => res.json({ message: 'API Foundry Invest Funcionando!' })); // Nome atualizado

// --- Rotas de Autenticação (/api/auth) ---
const authRouter = express.Router();
authRouter.post('/register', async (req, res) => {
    try {
        const { name, email, password, confirmPassword, securityQuestion, securityAnswer, referralCodeProvided } = req.body;
        if (!name || !email || !password || !confirmPassword || !securityQuestion || !securityAnswer) {
            return res.status(400).json({ m: 'Todos os campos marcados com * são obrigatórios.' });
        }
        if (password !== confirmPassword) return res.status(400).json({ m: 'As senhas fornecidas não coincidem.' });
        if (password.length < 6) return res.status(400).json({ m: 'A senha deve ter no mínimo 6 caracteres.' });

        const normalizedEmail = email.toLowerCase();
        let existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) return res.status(400).json({ m: 'Este endereço de email já está em uso.' });

        let referredByUser = null;
        if (referralCodeProvided && referralCodeProvided.trim() !== '') {
            referredByUser = await User.findOne({ referralCode: referralCodeProvided.trim().toUpperCase() });
            if (!referredByUser) {
                // Não bloqueia o registro, mas avisa no console. Poderia retornar erro se o código for obrigatório ou inválido.
                console.warn(`Código de indicação "${referralCodeProvided}" fornecido mas não encontrado.`);
            }
        }

        const systemSettings = await getOrInitializeSystemSettings();
        let initialBalance = 0;
        let registrationBonusApplied = 0;
        let userIsEligibleForBonus = true; // Por padrão, novos usuários são elegíveis

        if (systemSettings.isRegistrationBonusActive && systemSettings.registrationBonusAmount > 0 && userIsEligibleForBonus) {
            initialBalance += systemSettings.registrationBonusAmount;
            registrationBonusApplied = systemSettings.registrationBonusAmount;
            userIsEligibleForBonus = false; // Bônus aplicado, não mais elegível
        }

        const newUser = new User({
            name, email: normalizedEmail, password, securityQuestion, securityAnswer,
            referredBy: referredByUser ? referredByUser._id : null,
            balance: initialBalance,
            isEligibleForRegistrationBonus: userIsEligibleForBonus 
        });
        await newUser.save();

        if (registrationBonusApplied > 0) {
            await createTransactionEntry(newUser._id, 'registration_bonus', registrationBonusApplied, 'Bônus de Registro', 'completed', 0, newUser.balance);
            await createUserNotification(newUser._id, 'Bem-vindo à Foundry Invest!', `Você recebeu um bônus de registro de ${registrationBonusApplied.toFixed(2)} MT!`, 'success', '/wallet');
        }
        if (referredByUser) {
            await createUserNotification(referredByUser._id, 'Nova Indicação!', `${newUser.name} registrou-se usando seu código de indicação.`, 'info', '/referrals');
        }
        res.status(201).json({ m: 'Usuário registrado com sucesso!', userId: newUser._id });

    } catch (error) {
        console.error("Erro no registro de usuário:", error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ m: "Erro de validação nos dados fornecidos.", e: Object.values(error.errors).map(val => val.message) });
        }
        res.status(500).json({ m: 'Ocorreu um erro no servidor ao tentar registrar o usuário.' });
    }
});
authRouter.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ m: 'Email e senha são obrigatórios.' });

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(401).json({ m: 'Credenciais inválidas.' }); // Usuário não encontrado
        if (user.status !== 'active') return res.status(403).json({ m: `Sua conta está ${user.status}. Contacte o suporte.` });
        
        const MAX_FAILED_ATTEMPTS = 5;
        const LOCK_TIME = 15 * 60 * 1000; // 15 minutos em milissegundos

        if (user.lockUntil && user.lockUntil > Date.now()) {
            return res.status(403).json({ m: `Conta bloqueada devido a múltiplas tentativas falhas. Tente novamente em ${Math.ceil((user.lockUntil - Date.now()) / 60000)} minutos.` });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            user.failedLoginAttempts += 1;
            if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
                user.lockUntil = Date.now() + LOCK_TIME;
                await createUserNotification(user._id, "Conta Temporariamente Bloqueada", "Sua conta foi bloqueada por 15 minutos devido a múltiplas tentativas de login malsucedidas.", 'error');
            }
            await user.save();
            return res.status(401).json({ m: 'Credenciais inválidas.' });
        }

        user.failedLoginAttempts = 0; // Reseta tentativas falhas
        user.lockUntil = undefined; // Remove bloqueio
        user.lastLoginAt = Date.now();
        await user.save();

        const payload = { user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

        res.json({ m: "Login bem-sucedido!", token: token, user: payload.user });
    } catch (error) {
        console.error("Erro no login:", error);
        res.status(500).json({ m: 'Erro no servidor durante o login.' });
    }
});
authRouter.post('/recover/request-question', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ m: "O endereço de email é obrigatório." });
        const user = await User.findOne({ email: email.toLowerCase() }).select('securityQuestion email'); // Apenas busca a pergunta
        if (!user) return res.status(404).json({ m: "Endereço de email não encontrado em nosso sistema." });
        res.json({ email: user.email, securityQuestion: user.securityQuestion });
    } catch (error) {
        console.error("Erro ao solicitar pergunta de segurança:", error);
        res.status(500).json({ m: "Erro no servidor." });
    }
});
authRouter.post('/recover/verify-answer', async (req, res) => {
    try {
        const { email, securityAnswer } = req.body;
        if (!email || !securityAnswer) return res.status(400).json({ m: "Email e resposta de segurança são obrigatórios." });
        const user = await User.findOne({ email: email.toLowerCase() }); // Busca o usuário completo para comparar a resposta
        if (!user) return res.status(404).json({ m: "Endereço de email não encontrado." });

        const isAnswerMatch = await user.compareSecurityAnswer(securityAnswer);
        if (!isAnswerMatch) return res.status(401).json({ m: "Resposta de segurança incorreta." });

        const resetToken = user.createPasswordResetToken();
        await user.save({ validateBeforeSave: false }); // Salva o token de reset no usuário

        // Em um cenário real, você enviaria o resetToken por email. Aqui, apenas logamos para desenvolvimento.
        console.log(`Token de recuperação de senha para ${user.email} (uso em desenvolvimento): ${resetToken}`);
        // Não envie o token real na resposta JSON por motivos de segurança se o canal não for seguro
        // O frontend pode precisar de um token diferente para FORMULAR o pedido de reset, não o token de reset em si.
        // Para simplificar este exemplo, vamos assumir que o frontend manipulará o resetToken diretamente (não ideal para produção).
        res.json({ m: "Resposta verificada com sucesso. Um token de redefinição foi gerado e tem validade de 15 minutos.", resetTokenForFormSubmission: resetToken });
    } catch (error) {
        console.error("Erro ao verificar resposta de segurança:", error);
        res.status(500).json({ m: "Erro no servidor." });
    }
});
authRouter.post('/recover/reset-password', async (req, res) => {
    try {
        const { token, newPassword, confirmNewPassword } = req.body;
        if (!token || !newPassword || !confirmNewPassword) return res.status(400).json({ m: "Token e novas senhas são obrigatórios." });
        if (newPassword.length < 6) return res.status(400).json({m:"Nova senha deve ter no mínimo 6 caracteres."});
        if (newPassword !== confirmNewPassword) return res.status(400).json({ m: "As novas senhas não coincidem." });

        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).json({ m: "Token de redefinição de senha inválido ou expirado." });

        user.password = newPassword; // O hook pre-save fará o hash
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        user.failedLoginAttempts = 0; // Reseta tentativas de login
        user.lockUntil = undefined;   // Remove bloqueio
        await user.save();
        await createUserNotification(user._id,"Senha Redefinida com Sucesso","Sua senha foi redefinida e você já pode fazer login com a nova senha.",'success');
        res.json({ m: "Senha atualizada com sucesso. Você já pode fazer login." });
    } catch (error) {
        console.error("Erro ao redefinir senha:", error);
        res.status(500).json({ m: "Erro no servidor." });
    }
});
app.use('/api/auth', authRouter);

// --- Rotas de Perfil do Usuário (/api/users) ---
const userRouter = express.Router();
userRouter.use(protectRoute); // Protege todas as rotas de /api/users
userRouter.get('/profile', async (req, res) => {
    try {
        // O ID do usuário vem de req.user.id (definido pelo middleware protectRoute)
        const user = await User.findById(req.user.id).select('-password -securityQuestion -securityAnswer -passwordResetToken -passwordResetExpires -failedLoginAttempts -lockUntil -__v');
        if (!user) return res.status(404).json({ m: "Usuário não encontrado." });
        res.json(user);
    } catch (error) {
        console.error("Erro ao buscar perfil do usuário:", error);
        res.status(500).json({ m: "Erro ao buscar informações do perfil." });
    }
});
userRouter.put('/profile', async (req, res) => {
    try {
        const { name } = req.body; // Por enquanto, permite apenas atualização do nome
        const updateData = {};
        if (name && name.trim().length >= 3) {
            updateData.name = name.trim();
        } else if (name) { // Se 'name' foi enviado mas é inválido
            return res.status(400).json({ m: "O nome deve ter pelo menos 3 caracteres." });
        }

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ m: "Nenhum dado válido fornecido para atualização." });
        }

        const updatedUser = await User.findByIdAndUpdate(req.user.id, updateData, { new: true, runValidators: true }).select('-password -securityQuestion -securityAnswer -__v');
        if (!updatedUser) return res.status(404).json({ m: "Usuário não encontrado." });
        
        // Atualiza o objeto de usuário no payload do token para futuras requisições (opcional, depende da estratégia de sessão)
        // Ou instrui o frontend a buscar o perfil novamente ou atualizar o nome localmente.
        res.json({ m: "Perfil atualizado com sucesso.", user: updatedUser });
    } catch (error) {
        console.error("Erro ao atualizar perfil:", error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ m: "Dados inválidos.", e: Object.values(error.errors).map(val => val.message) });
        }
        res.status(500).json({ m: "Erro ao atualizar perfil." });
    }
});
userRouter.put('/change-password', async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmNewPassword } = req.body;
        if (!currentPassword || !newPassword || !confirmNewPassword) {
            return res.status(400).json({ m: "Todos os campos de senha são obrigatórios." });
        }
        if (newPassword.length < 6) return res.status(400).json({m:"Nova senha deve ter no mínimo 6 caracteres."});
        if (newPassword !== confirmNewPassword) return res.status(400).json({ m: "As novas senhas não coincidem." });

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ m: "Usuário não encontrado." });

        const isMatch = await user.comparePassword(currentPassword);
        if (!isMatch) return res.status(401).json({ m: "Senha atual incorreta." });

        // Verifica se a nova senha é diferente da atual
        if (await bcrypt.compare(newPassword, user.password)) {
            return res.status(400).json({m: "A nova senha não pode ser igual à senha atual."});
        }

        user.password = newPassword; // O hook pre-save fará o hash
        await user.save();
        await createUserNotification(user._id,"Senha Alterada com Sucesso","Sua senha foi alterada. Por segurança, recomendamos que anote sua nova senha em local seguro.",'success');
        res.json({ m: "Senha alterada com sucesso." });
    } catch (error) {
        console.error("Erro ao alterar senha:", error);
        res.status(500).json({ m: "Erro ao alterar senha." });
    }
});
userRouter.get('/referral-details', async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('referralCode');
        if (!user) return res.status(404).json({ m: "Usuário não encontrado." });

        const totalReferredUsers = await User.countDocuments({ referredBy: req.user.id });
        
        const referralBonusesResult = await Transaction.aggregate([
            { $match: { user: new mongoose.Types.ObjectId(req.user.id), type: { $in: ['referral_bonus_plan', 'referral_bonus_profit'] } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        
        const totalReferralBonusEarned = referralBonusesResult.length > 0 ? referralBonusesResult[0].total.toFixed(2) : "0.00";

        res.json({
            rC: user.referralCode,      // Seu código de indicação
            tRU: totalReferredUsers,    // Total de usuários que você indicou
            tRBE: totalReferralBonusEarned // Total de bônus que você ganhou por indicações
        });
    } catch (error) {
        console.error("Erro ao buscar detalhes de indicação:", error);
        res.status(500).json({ m: "Erro ao buscar detalhes de indicação." });
    }
});
userRouter.get('/transactions', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 15;
        const skip = (page - 1) * limit;
        const transactionTypeFilter = req.query.type;

        let query = { user: req.user.id };
        if (transactionTypeFilter) {
            query.type = transactionTypeFilter;
        }

        const transactions = await Transaction.find(query).sort({ transactionDate: -1 }).skip(skip).limit(limit);
        const totalTransactions = await Transaction.countDocuments(query);

        res.json({
            transactions: transactions,
            currentPage: page,
            totalPages: Math.ceil(totalTransactions / limit),
            totalCount: totalTransactions
        });
    } catch (error) {
        console.error("Erro ao buscar transações:", error);
        res.status(500).json({ m: "Erro ao buscar transações." });
    }
});
userRouter.get('/notifications', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const notifications = await Notification.find({ user: req.user.id }).sort({ createdAt: -1 }).skip(skip).limit(limit);
        const totalNotifications = await Notification.countDocuments({ user: req.user.id });
        const unreadCount = await Notification.countDocuments({ user: req.user.id, isRead: false });

        res.json({
            notifications: notifications,
            currentPage: page,
            totalPages: Math.ceil(totalNotifications / limit),
            totalCount: totalNotifications,
            unreadCount: unreadCount
        });
    } catch (error) {
        console.error("Erro ao buscar notificações:", error);
        res.status(500).json({ m: "Erro ao buscar notificações." });
    }
});
userRouter.put('/notifications/:id/read', async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de notificação inválido."});
        const notification = await Notification.findOneAndUpdate(
            { _id: req.params.id, user: req.user.id },
            { isRead: true },
            { new: true }
        );
        if (!notification) return res.status(404).json({ m: "Notificação não encontrada ou não pertence ao usuário." });
        res.json({ m: "Notificação marcada como lida.", notification: notification });
    } catch (error) {
        console.error("Erro ao marcar notificação como lida:", error);
        res.status(500).json({ m: "Erro ao atualizar notificação." });
    }
});
userRouter.put('/notifications/read-all', async (req, res) => {
    try {
        await Notification.updateMany(
            { user: req.user.id, isRead: false },
            { isRead: true }
        );
        res.json({ m: "Todas as notificações foram marcadas como lidas." });
    } catch (error) {
        console.error("Erro ao marcar todas as notificações como lidas:", error);
        res.status(500).json({ m: "Erro ao atualizar notificações." });
    }
});
app.use('/api/users', userRouter);


// --- Rotas de Admin (/api/admin) ---
const adminRouter = express.Router();
adminRouter.use(protectRoute, adminOnly); // Protege todas as rotas de admin
adminRouter.get('/settings', async (req, res) => {
    try {
        const settings = await getOrInitializeSystemSettings();
        res.json(settings);
    } catch (error) {
        res.status(500).json({ m: "Erro ao buscar configurações do sistema." });
    }
});
adminRouter.put('/settings', async (req, res) => {
    try {
        const updates = req.body;
        // Validação básica dos tipos de dados esperados
        const validNumberFields = ['registrationBonusAmount', 'referralPlanPurchaseBonusPercentage', 'referralDailyProfitBonusPercentage', 'minWithdrawalAmount', 'maxWithdrawalAmount', 'withdrawalFeePercentage', 'defaultPlanDuration'];
        const validBooleanFields = ['isReferralSystemActive', 'isRegistrationBonusActive'];
        
        const settings = await SystemSettings.findOne({ singletonId: 'main_settings' });
        if (!settings) return res.status(404).json({ m: "Configurações do sistema não encontradas." });

        for (const key in updates) {
            if (settings.hasOwnProperty(key) && key !== 'singletonId' && key !== '_id' && key !== '__v' && key !== 'lastUpdatedAt') {
                 if (validNumberFields.includes(key)) {
                    const numValue = parseFloat(updates[key]);
                    if (!isNaN(numValue) && numValue >= 0 && (key.includes('Percentage') ? numValue <= 1 : true) ) {
                        settings[key] = numValue;
                    } else { return res.status(400).json({m: `Valor inválido para ${key}. Deve ser um número não negativo (e <= 1 para percentagens).`});}
                } else if (validBooleanFields.includes(key)) {
                    settings[key] = (updates[key] === true || updates[key] === 'true');
                }
                // Adicionar mais tipos se necessário (strings, etc.)
            }
        }
        settings.lastUpdatedAt = Date.now();
        await settings.save();
        res.json({ m: "Configurações do sistema atualizadas!", settings: settings });
    } catch (error) {
        console.error("Erro ao atualizar configurações:", error);
        res.status(500).json({ m: "Erro ao atualizar configurações." });
    }
});
adminRouter.get('/users', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 15;
        const skip = (page - 1) * limit;
        const { search, role, status, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;
        
        let query = {};
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ];
        }
        if (role) query.role = role;
        if (status) query.status = status;
        
        const sortOptions = {};
        sortOptions[sortBy] = sortOrder === 'asc' ? 1 : -1;

        const users = await User.find(query).select('-password -securityAnswer').sort(sortOptions).skip(skip).limit(limit).populate('referredBy', 'name email');
        const totalUsers = await User.countDocuments(query);
        res.json({ users: users, currentPage: page, totalPages: Math.ceil(totalUsers / limit), totalCount: totalUsers });
    } catch (error) {
        console.error("Erro ao listar usuários (admin):", error);
        res.status(500).json({ m: "Erro ao listar usuários." });
    }
});
adminRouter.get('/users/:id', async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de usuário inválido."});
        const user = await User.findById(req.params.id).select('-password -securityAnswer').populate('referredBy', 'name email');
        if (!user) return res.status(404).json({ m: "Usuário não encontrado." });
        
        // Adicional: Buscar outras informações relacionadas ao usuário
        const investments = await UserInvestment.find({user: user._id}).populate('plan', 'name price_mt').sort({startDate: -1});
        const transactions = await Transaction.find({user: user._id}).sort({transactionDate: -1}).limit(20); // Últimas 20
        const withdrawalRequests = await WithdrawalRequest.find({user: user._id}).sort({requestedAt: -1}).limit(10);
        const depositRequests = await DepositRequest.find({user: user._id}).sort({requestedAt: -1}).limit(10);

        res.json({ user: user, investments, transactions, withdrawalRequests, depositRequests });
    } catch (error) {
        console.error("Erro ao buscar detalhes do usuário (admin):", error);
        res.status(500).json({ m: "Erro ao buscar detalhes do usuário." });
    }
});
adminRouter.put('/users/:id/update-details', async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de usuário inválido."});
        const { name, email, role, status, balanceAdjustment, adjustmentReason } = req.body;
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ m: "Usuário não encontrado." });

        let emailChanged = false;
        if (name && name.trim() !== '') user.name = name.trim();
        if (email && email.toLowerCase() !== user.email) {
            const existingEmailUser = await User.findOne({ email: email.toLowerCase() });
            if (existingEmailUser && existingEmailUser._id.toString() !== user._id.toString()) {
                return res.status(400).json({ m: "Este email já está em uso por outro usuário." });
            }
            user.email = email.toLowerCase();
            emailChanged = true;
        }
        if (role && ['user', 'admin'].includes(role)) user.role = role; // Cuidado ao alterar role
        if (status && ['active', 'suspended', 'banned', 'pending_verification'].includes(status)) {
            if (user.status !== status && status === 'active') { // Se reativando
                user.failedLoginAttempts = 0;
                user.lockUntil = null;
            }
            user.status = status;
        }

        if (balanceAdjustment !== undefined && typeof balanceAdjustment === 'number' && balanceAdjustment !== 0) {
            if (!adjustmentReason || adjustmentReason.trim() === '') {
                return res.status(400).json({m: "A razão para o ajuste de saldo é obrigatória."});
            }
            const oldBalance = user.balance;
            const newBalance = user.balance + balanceAdjustment;
            if (newBalance < 0) return res.status(400).json({m: "Ajuste resultaria em saldo negativo."});
            user.balance = newBalance;
            await createTransactionEntry(user._id, balanceAdjustment > 0 ? 'admin_credit' : 'admin_debit', balanceAdjustment, `Ajuste de Administrador: ${adjustmentReason}`, 'completed', oldBalance, newBalance);
            await createUserNotification(user._id, "Saldo Ajustado pelo Administrador", `Seu saldo foi ajustado em ${balanceAdjustment.toFixed(2)} MT. Razão: ${adjustmentReason}.`, 'info');
        }
        
        await user.save();
        const userToReturn = user.toObject(); // Converte para objeto para poder deletar campos
        delete userToReturn.password;
        delete userToReturn.securityAnswer;
        res.json({ m: "Detalhes do usuário atualizados.", user: userToReturn, emailChanged: emailChanged });
    } catch (error) {
        console.error("Erro ao atualizar detalhes do usuário (admin):", error);
        res.status(500).json({ m: "Erro ao atualizar detalhes do usuário." });
    }
});
adminRouter.put('/users/:id/status', async (req, res) => { // Rota dedicada para mudar status
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de usuário inválido."});
        const { status, reason } = req.body;
        if (!status || !['active', 'suspended', 'banned'].includes(status)) {
            return res.status(400).json({m: "Status fornecido é inválido. Use 'active', 'suspended', ou 'banned'."});
        }
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({m: "Usuário não encontrado."});

        // Lógica para não desativar o último admin ativo
        if (user.role === 'admin' && status !== 'active') {
            const activeAdminCount = await User.countDocuments({role: 'admin', status: 'active'});
            if (activeAdminCount <= 1 && user.id === req.user.id) { // Se ele for o último admin ativo e tentando se desativar
                return res.status(400).json({m: "Não é possível desativar o único administrador ativo."});
            }
        }

        user.status = status;
        if (status === 'active') { // Se reativando, reseta tentativas de login e bloqueio
            user.failedLoginAttempts = 0;
            user.lockUntil = null;
        }
        await user.save();
        await createUserNotification(user._id, 
            "Status da Sua Conta Alterado", 
            `O status da sua conta foi alterado para: ${status}. ${reason ? 'Razão: '+reason : ''}`, 
            status === 'active' ? 'success' : 'warning'
        );
        const userToReturn = user.toObject(); delete userToReturn.password; delete userToReturn.securityAnswer;
        res.json({ m: `Status do usuário alterado para ${status}.`, user: userToReturn });
    } catch (error) {
        console.error("Erro ao alterar status do usuário (admin):", error);
        res.status(500).json({ m: "Erro ao alterar status do usuário." });
    }
});
adminRouter.post('/deposit-methods', async (req, res) => {
    try {
        const { name, instructions, paymentInfo /*, outros campos do DepositMethodSchema */ } = req.body;
        if (!name || !instructions || !paymentInfo ) return res.status(400).json({m: "Nome, instruções e informações de pagamento são obrigatórios."});
        // Adicionar mais validações se necessário para minAmount, maxAmount etc.
        const newMethod = new DepositMethod(req.body);
        await newMethod.save();
        res.status(201).json({ m: "Novo método de depósito adicionado.", method: newMethod });
    } catch (error) {
        if (error.code === 11000) return res.status(400).json({m: "Um método de depósito com este nome já existe."});
        console.error("Erro ao adicionar método de depósito:", error);
        res.status(500).json({ m: "Erro ao adicionar método de depósito." });
    }
});
adminRouter.get('/deposit-methods', async (req, res) => {
    try {
        const methods = await DepositMethod.find().sort({ name: 1 });
        res.json(methods);
    } catch (error) {
        console.error("Erro ao listar métodos de depósito:", error);
        res.status(500).json({ m: "Erro ao listar métodos de depósito." });
    }
});
adminRouter.put('/deposit-methods/:id', async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de método inválido."});
        const updatedMethod = await DepositMethod.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!updatedMethod) return res.status(404).json({m: "Método de depósito não encontrado."});
        res.json({ m: "Método de depósito atualizado.", method: updatedMethod });
    } catch (error) {
        if (error.code === 11000) return res.status(400).json({m: "Um método de depósito com este nome já existe."});
        console.error("Erro ao atualizar método de depósito:", error);
        res.status(500).json({ m: "Erro ao atualizar método de depósito." });
    }
});
adminRouter.delete('/deposit-methods/:id', async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de método inválido."});
        const deletedMethod = await DepositMethod.findByIdAndDelete(req.params.id);
        if (!deletedMethod) return res.status(404).json({m: "Método de depósito não encontrado."});
        res.json({ m: "Método de depósito removido." });
    } catch (error) {
        console.error("Erro ao remover método de depósito:", error);
        res.status(500).json({ m: "Erro ao remover método de depósito." });
    }
});
adminRouter.get('/deposit-requests', async (req, res) => {
    try {
        const { status, page = 1, limit = 10 } = req.query;
        const query = status ? { status } : {};
        const requests = await DepositRequest.find(query)
            .populate('user', 'name email')
            .populate('depositMethod', 'name')
            .sort({ requestedAt: -1 })
            .limit(parseInt(limit))
            .skip((parseInt(page) - 1) * parseInt(limit));
        const count = await DepositRequest.countDocuments(query);
        res.json({ requests: requests, totalPages: Math.ceil(count / limit), currentPage: parseInt(page) });
    } catch (error) {
        console.error("Erro ao buscar solicitações de depósito (admin):", error);
        res.status(500).json({ m: "Erro ao buscar solicitações de depósito." });
    }
});
adminRouter.put('/deposit-requests/:id/process', async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de solicitação inválido."});
        const { status, adminNotes } = req.body; // adminNotes pode ser a razão da rejeição
        if (!['approved', 'rejected'].includes(status)) {
            return res.status(400).json({m: "Status inválido. Deve ser 'approved' ou 'rejected'."});
        }
        const request = await DepositRequest.findById(req.params.id).populate('depositMethod', 'name');
        if (!request || request.status !== 'pending') {
            return res.status(404).json({m: "Solicitação não encontrada ou já processada."});
        }
        
        request.status = status;
        request.adminNotes = adminNotes || '';
        request.processedAt = Date.now();
        
        const user = await User.findById(request.user);
        if (!user) return res.status(404).json({m: "Usuário da solicitação não encontrado."});

        if (status === 'approved') {
            const balanceBefore = user.balance;
            user.balance += request.amount;
            await user.save();
            await createTransactionEntry(user._id, 'deposit_approved', request.amount, 
                `Depósito Aprovado via ${request.depositMethod?.name || 'N/A'}. Ref: ${request.userTransactionReference}`, 
                'completed', balanceBefore, user.balance, {relatedDepositRequest: request._id});
            await createUserNotification(user._id, "Depósito Aprovado", `Seu depósito de ${request.amount.toFixed(2)} MT foi aprovado e creditado em sua conta.`, 'success', '/transactions');
        } else { // status === 'rejected'
            request.rejectionReason = adminNotes || 'Não especificado pelo administrador.';
            await createUserNotification(user._id, "Depósito Rejeitado", `Sua solicitação de depósito de ${request.amount.toFixed(2)} MT foi rejeitada. Razão: ${request.rejectionReason}`, 'error');
        }
        await request.save();
        res.json({ m: `Solicitação de depósito marcada como ${status}.`, request: request });
    } catch (error) {
        console.error("Erro ao processar solicitação de depósito (admin):", error);
        res.status(500).json({ m: "Erro ao processar solicitação." });
    }
});
adminRouter.get('/withdrawal-requests', async (req, res) => {
    try {
        const { status, page = 1, limit = 10 } = req.query;
        const query = status ? { status } : {};
        const requests = await WithdrawalRequest.find(query)
            .populate('user', 'name email balance') // Inclui saldo para verificação rápida
            .sort({ requestedAt: -1 })
            .limit(parseInt(limit))
            .skip((parseInt(page) - 1) * parseInt(limit));
        const count = await WithdrawalRequest.countDocuments(query);
        res.json({ requests: requests, totalPages: Math.ceil(count / limit), currentPage: parseInt(page) });
    } catch (error) {
        console.error("Erro ao buscar solicitações de saque (admin):", error);
        res.status(500).json({ m: "Erro ao buscar solicitações de saque." });
    }
});
adminRouter.put('/withdrawal-requests/:id/process', async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de solicitação inválido."});
        const { status, adminNotes, transactionIdFromProvider } = req.body;
        if (!['approved', 'processing', 'completed', 'rejected', 'failed'].includes(status)) {
            return res.status(400).json({m: "Status de saque inválido."});
        }
        const request = await WithdrawalRequest.findById(req.params.id);
        if (!request) return res.status(404).json({m: "Solicitação de saque não encontrada."});
        
        const user = await User.findById(request.user);
        if (!user) return res.status(404).json({m: "Usuário da solicitação não encontrado."});

        const oldStatus = request.status;
        request.status = status;
        request.adminNotes = adminNotes || request.adminNotes; // Mantém notas antigas se não for fornecida nova
        if (transactionIdFromProvider) request.transactionIdFromProvider = transactionIdFromProvider;
        
        let notificationMessage = '';
        let notificationType = 'info';

        if (status === 'approved' && oldStatus === 'pending') {
            request.processedAt = Date.now();
            notificationMessage = `Sua solicitação de saque de ${request.amount.toFixed(2)} MT foi aprovada e está aguardando processamento pelo provedor.`;
            notificationType = 'success';
        } else if (status === 'processing' && oldStatus !== 'processing') {
            request.processedAt = Date.now(); // Pode ser a mesma data da aprovação ou posterior
            notificationMessage = `Sua solicitação de saque de ${request.amount.toFixed(2)} MT está sendo processada.`;
            notificationType = 'info';
        } else if (status === 'completed' && oldStatus !== 'completed') {
            // Apenas debita o saldo e cria transação quando o status muda para 'completed'
            // Verifica saldo ANTES de debitar
            const systemSettings = await getOrInitializeSystemSettings();
            const feeAlreadyCalculated = request.feeCharged; // A taxa já foi calculada na criação da solicitação
            // const totalDebitAmount = request.amount; // O usuário solicitou X, a taxa já foi descontada disso ou o valor solicitado é o bruto?
                                                // Assumindo que request.amount é o valor que o usuário quer receber, e a taxa é SOBRE ele
                                                // Ou, request.amount é o valor bruto, e request.netAmount é o que ele recebe.
                                                // Pelo schema, feeCharged é calculado e netAmount = amount - feeCharged.
                                                // O usuário pede `amount`, o saldo debitado é `amount`. A taxa já estava inclusa na verificação de saldo.

            if (user.balance < request.amount) { // Verifica novamente o saldo bruto
                request.status = 'failed'; // Volta para failed se o saldo não for suficiente AGORA
                request.rejectionReason = 'Saldo insuficiente no momento do processamento final.';
                await request.save();
                await createUserNotification(user._id,"Falha no Saque",`Saque de ${request.amount.toFixed(2)} MT falhou por saldo insuficiente no processamento final.`,'error');
                return res.status(400).json({m:"Saldo do usuário tornou-se insuficiente."});
            }

            const balanceBefore = user.balance;
            user.balance -= request.amount; // Debita o valor bruto que foi solicitado
            await user.save();

            request.completedAt = Date.now();
            // feeCharged e netAmount já devem ter sido definidos na criação do request.
            
            await createTransactionEntry(user._id, 'withdrawal_processed', -request.amount, 
                `Saque de ${request.amount.toFixed(2)} MT (${request.withdrawalMethodType}) processado.`, 
                'completed', balanceBefore, user.balance, {relatedWithdrawalRequest: request._id});
            
            // Se a taxa não foi zero, registra a transação da taxa também.
            // A taxa é um débito adicional.
            // Assumindo que a verificação de saldo inicial (u.balance < totalDebit) na criação do request já considerou a taxa.
            // Se feeCharged for 0, esta transação não é criada.
            if (request.feeCharged > 0) {
                // Esta transação de taxa já foi implicitamente considerada no débito do saldo principal se o `amount` era líquido.
                // Se `amount` era bruto e `netAmount` era o valor pago, então o débito do saldo deve ser `amount`, e a taxa é parte disso.
                // A lógica atual: `user.balance -= request.amount;`. Se `request.amount` é o valor bruto, então está ok.
                // Se a taxa é ADICIONAL ao valor do saque, então o débito deveria ser request.amount + request.feeCharged.
                // Vou assumir que `request.amount` é o valor bruto que sai da conta do usuário.
            }

            notificationMessage = `Seu saque de ${request.amount.toFixed(2)} MT foi concluído com sucesso.`;
            notificationType = 'success';
        } else if (status === 'rejected' || status === 'failed') {
            request.rejectionReason = adminNotes || (status === 'rejected' ? 'Rejeitado pelo administrador.' : 'Falha no processamento.');
            notificationMessage = `Sua solicitação de saque de ${request.amount.toFixed(2)} MT foi ${status === 'rejected' ? 'rejeitada' : 'marcada como falha'}. Razão: ${request.rejectionReason}`;
            notificationType = 'error';
        }
        
        await request.save();
        if (notificationMessage) {
            await createUserNotification(user._id, "Atualização do Status de Saque", notificationMessage, notificationType, '/transactions');
        }
        res.json({ m: `Status da solicitação de saque atualizado para ${status}.`, request: request });
    } catch (error) {
        console.error("Erro ao processar solicitação de saque (admin):", error);
        res.status(500).json({ m: "Erro ao processar solicitação de saque." });
    }
});
adminRouter.get('/investments', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 15;
        const skip = (page - 1) * limit;
        const { userId, planId, isActive, sort = '-startDate' } = req.query; // Default sort
        
        let query = {};
        if (userId && mongoose.Types.ObjectId.isValid(userId)) query.user = userId;
        if (planId && mongoose.Types.ObjectId.isValid(planId)) query.plan = planId;
        if (isActive !== undefined) query.isActive = (isActive === 'true');

        const investments = await UserInvestment.find(query)
            .populate('user', 'name email')
            .populate('plan', 'name')
            .sort(sort) // Ex: '-startDate' ou 'startDate'
            .skip(skip)
            .limit(limit);
        const totalInvestments = await UserInvestment.countDocuments(query);
        res.json({ investments: investments, currentPage: page, totalPages: Math.ceil(totalInvestments / limit), totalCount: totalInvestments });
    } catch (error) {
        console.error("Erro ao listar investimentos (admin):", error);
        res.status(500).json({ m: "Erro ao listar investimentos." });
    }
});
adminRouter.get('/investments/:id', async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de investimento inválido."});
        const investment = await UserInvestment.findById(req.params.id)
            .populate('user', 'name email balance')
            .populate('plan'); // Popula o plano completo
        if (!investment) return res.status(404).json({m: "Investimento não encontrado."});
        res.json(investment);
    } catch (error) {
        console.error("Erro ao buscar detalhe do investimento (admin):", error);
        res.status(500).json({ m: "Erro ao buscar detalhe do investimento." });
    }
});
adminRouter.put('/investments/:id/status', async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de investimento inválido."});
        const { isActive, adminNotes } = req.body;
        if (typeof isActive !== 'boolean') {
            return res.status(400).json({m: "O campo 'isActive' (booleano) é obrigatório."});
        }
        const investment = await UserInvestment.findById(req.params.id).populate('planSnapshot'); // Popula para ter o nome no snapshot
        if (!investment) return res.status(404).json({m: "Investimento não encontrado."});

        investment.isActive = isActive;
        // Poderia adicionar um campo `adminNotes` ao UserInvestmentSchema se necessário.
        await investment.save();
        await createUserNotification(investment.user, 
            `Status do Investimento Alterado`, 
            `Seu plano de investimento "${investment.planSnapshot.name}" foi marcado como ${isActive ? 'Ativo' : 'Inativo'} pelo administrador. ${adminNotes || ''}`, 
            isActive ? 'info' : 'warning'
        );
        res.json({ m: "Status do investimento atualizado.", investment: investment });
    } catch (error) {
        console.error("Erro ao atualizar status do investimento (admin):", error);
        res.status(500).json({ m: "Erro ao atualizar status do investimento." });
    }
});
adminRouter.get('/stats/overview', async (req,res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalActivePlans = await Plan.countDocuments({isActive: true});
        const totalActiveInvestments = await UserInvestment.countDocuments({isActive: true});
        
        const totalDepositsResult = await Transaction.aggregate([ {$match:{type:'deposit_approved'}}, {$group:{_id:null,total:{$sum:'$amount'}}} ]);
        const totalWithdrawalsResult = await WithdrawalRequest.aggregate([ {$match:{status:'completed'}}, {$group:{_id:null,total:{$sum:'$netAmount'}}} ]); // Soma o netAmount
        const totalProfitsCollectedResult = await Transaction.aggregate([ {$match:{type:'profit_collection'}}, {$group:{_id:null,total:{$sum:'$amount'}}} ]);

        const pendingWithdrawals = await WithdrawalRequest.countDocuments({status: 'pending'});
        const pendingDeposits = await DepositRequest.countDocuments({status: 'pending'});

        res.json({
            totalUsers: totalUsers,
            totalActiveSystemPlans: totalActivePlans, // Quantos tipos de planos estão ativos no sistema
            totalActiveUserInvestments: totalActiveInvestments, // Quantos investimentos de usuários estão ativos
            totalDeposited: totalDepositsResult[0]?.total || 0,
            totalWithdrawn: totalWithdrawalsResult[0]?.total || 0,
            totalProfitsCollectedByUsers: totalProfitsCollectedResult[0]?.total || 0,
            pendingWithdrawalRequests: pendingWithdrawals,
            pendingDepositRequests: pendingDeposits
        });
    } catch(error) {
        console.error("Erro ao buscar estatísticas gerais:", error);
        res.status(500).json({m:"Erro ao buscar estatísticas."});
    }
});
adminRouter.get('/stats/user-growth', async(req,res) => { // Crescimento de usuários
    try{
        const days = parseInt(req.query.days) || 30; // Padrão para os últimos 30 dias
        const today = new Date();
        today.setUTCHours(0,0,0,0); // Zera a hora para o início do dia UTC
        const dateLimit = new Date(today);
        dateLimit.setDate(today.getDate() - days);

        const userGrowth = await User.aggregate([
            {$match:{ createdAt: {$gte: dateLimit} }},
            {$group:{
                _id: { $dateToString:{format:"%Y-%m-%d", date:"$createdAt", timezone: "Africa/Maputo"} }, // Agrupa por dia no fuso de Maputo
                count: {$sum:1}
            }},
            {$sort:{_id:1}} // Ordena por data
        ]);
        res.json(userGrowth);
    }catch(error){
        console.error("Erro ao buscar estatísticas de crescimento de usuários:", error);
        res.status(500).json({m:"Erro ao buscar estatísticas de crescimento."});
    }
});
app.use('/api/admin', adminRouter);


// --- Rotas Públicas para Planos e Métodos de Depósito ---
const publicPlanRouter = express.Router();
publicPlanRouter.get('/', async (req, res) => {
    try {
        const plans = await Plan.find({ isActive: true }).sort({ price_mt: 1 }); // Ordena por preço, por exemplo
        res.json(plans);
    } catch (error) {
        console.error("Erro ao buscar planos públicos:", error);
        res.status(500).json({ m: "Erro ao buscar planos." });
    }
});
publicPlanRouter.get('/:id', async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de plano inválido."});
        const plan = await Plan.findById(req.params.id);
        if (!plan || !plan.isActive) return res.status(404).json({ m: "Plano não encontrado ou inativo." });
        res.json(plan);
    } catch (error) {
        console.error("Erro ao buscar plano público por ID:", error);
        res.status(500).json({ m: "Erro ao buscar plano." });
    }
});
app.use('/api/plans', publicPlanRouter);

const publicDepositMethodRouter = express.Router();
publicDepositMethodRouter.get('/', async (req, res) => {
    try {
        const methods = await DepositMethod.find({ isActive: true }).select('-createdAt -updatedAt -__v -accountDetailsSchema'); // Não expõe schema interno
        res.json(methods);
    } catch (error) {
        console.error("Erro ao buscar métodos de depósito públicos:", error);
        res.status(500).json({ m: "Erro ao buscar métodos de depósito." });
    }
});
app.use('/api/deposit-methods', publicDepositMethodRouter);


// --- Rotas para Usuário Submeter Solicitação de Depósito e Saque ---
const depositUserRouter = express.Router();
depositUserRouter.post('/request', async (req, res) => {
    try {
        const { amount, depositMethodId, userTransactionReference } = req.body;
        if (!amount || !depositMethodId || !userTransactionReference) {
            return res.status(400).json({m: "Valor, método de depósito e referência da transação são obrigatórios."});
        }
        if(!mongoose.Types.ObjectId.isValid(depositMethodId)) return res.status(400).json({m:"ID do método de depósito inválido."});

        const method = await DepositMethod.findById(depositMethodId);
        if (!method || !method.isActive) return res.status(404).json({m: "Método de depósito não encontrado ou inativo."});

        const parsedAmount = parseFloat(amount);
        if (isNaN(parsedAmount) || parsedAmount < method.minAmount || parsedAmount > method.maxAmount) {
            return res.status(400).json({m: `O valor do depósito deve estar entre ${method.minAmount} e ${method.maxAmount} ${method.currency}.`});
        }

        const newRequest = new DepositRequest({
            user: req.user.id,
            amount: parsedAmount,
            depositMethod: depositMethodId,
            userTransactionReference: userTransactionReference.trim()
            // userNotes pode ser adicionado se o frontend enviar
        });
        await newRequest.save();
        await createUserNotification(req.user.id, 
            "Solicitação de Depósito Recebida", 
            `Sua solicitação de depósito de ${newRequest.amount.toFixed(2)} ${newRequest.currency} foi recebida e está em processamento.`,
            'info',
            '/transactions' // Link para o histórico de transações ou depósitos
            );
        res.status(201).json({ m: "Solicitação de depósito recebida com sucesso. Aguarde o processamento.", request: newRequest });
    } catch (error) {
        console.error("Erro ao criar solicitação de depósito:", error);
        res.status(500).json({ m: "Erro ao processar sua solicitação de depósito." });
    }
});
app.use('/api/deposits', protectRoute, depositUserRouter);


const withdrawalUserRouter = express.Router();
withdrawalUserRouter.post('/request', async (req, res) => {
    try {
        const { amount, withdrawalMethodType, withdrawalAccountDetails } = req.body;
        if (!amount || !withdrawalMethodType || !withdrawalAccountDetails || typeof withdrawalAccountDetails !== 'object' || Object.keys(withdrawalAccountDetails).length === 0) {
            return res.status(400).json({m: "Valor, tipo de método de saque e detalhes da conta de saque são obrigatórios."});
        }
        const parsedAmount = parseFloat(amount);
        if (isNaN(parsedAmount) || parsedAmount <= 0) return res.status(400).json({m: "Valor de saque inválido."});
        
        const systemSettings = await getOrInitializeSystemSettings();
        if (parsedAmount < systemSettings.minWithdrawalAmount || parsedAmount > systemSettings.maxWithdrawalAmount) {
            return res.status(400).json({m: `O valor do saque deve estar entre ${systemSettings.minWithdrawalAmount} e ${systemSettings.maxWithdrawalAmount} MT.`});
        }

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({m: "Usuário não encontrado."});

        const feeCharged = parsedAmount * systemSettings.withdrawalFeePercentage;
        const totalAmountToDebit = parsedAmount; // O usuário pede X, e a taxa é calculada sobre X, mas X é o que sai do saldo dele. O netAmount é o que ele recebe.
                                              // Se a taxa é ADICIONAL, então totalAmountToDebit seria parsedAmount + feeCharged.
                                              // Pelo schema, feeCharged é calculado, e netAmount = amount - feeCharged.
                                              // A lógica mais comum é: usuário pede X, taxa T é X*P, usuário recebe X-T, saldo debita X.
                                              // Se o saldo deve debitar X+T, então a verificação de saldo abaixo precisa ser X+T.
                                              // Vou assumir que o `amount` que o usuário pede é o valor bruto que sai da conta dele,
                                              // e a taxa é calculada sobre esse valor, e o `netAmount` é o que ele realmente recebe.

        if (user.balance < parsedAmount) { // Verifica se tem o valor bruto do saque
            return res.status(400).json({m: "Saldo insuficiente para cobrir o valor do saque."});
        }
        
        // Verifica se já existe um saque pendente
        const pendingWithdrawal = await WithdrawalRequest.findOne({ user: req.user.id, status: 'pending' });
        if (pendingWithdrawal) return res.status(400).json({m: "Você já possui uma solicitação de saque pendente. Aguarde o processamento."});

        const newRequest = new WithdrawalRequest({
            user: req.user.id,
            amount: parsedAmount,
            withdrawalMethodType: withdrawalMethodType,
            withdrawalAccountDetails: withdrawalAccountDetails,
            feeCharged: feeCharged, // A taxa é calculada aqui
            netAmount: parsedAmount - feeCharged // O valor líquido que o usuário receberá
        });
        await newRequest.save();
        await createUserNotification(req.user.id, 
            "Solicitação de Saque Recebida", 
            `Sua solicitação de saque de ${newRequest.amount.toFixed(2)} MT está em processamento. Taxa: ${feeCharged.toFixed(2)} MT. Líquido: ${newRequest.netAmount.toFixed(2)} MT.`,
            'info',
            '/transactions'
            );
        res.status(201).json({ m: "Solicitação de saque recebida com sucesso. Aguarde o processamento.", request: newRequest });
    } catch (error) {
        console.error("Erro ao criar solicitação de saque:", error);
        res.status(500).json({ m: "Erro ao processar sua solicitação de saque." });
    }
});
app.use('/api/withdrawals', protectRoute, withdrawalUserRouter);


// --- ROTAS DE INVESTIMENTOS DO USUÁRIO (/api/investments) ---
const investmentRouter = express.Router(); // Router já definido, OK.

investmentRouter.post('/', async (req, res) => {
    try {
        const { planId } = req.body;
        if (!planId || !mongoose.Types.ObjectId.isValid(planId)) return res.status(400).json({m:"ID do plano inválido."});
        
        const plan = await Plan.findOne({ _id: planId, isActive: true });
        if (!plan) return res.status(404).json({m:"Plano não encontrado ou está inativo."});
        
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({m:"Usuário não encontrado."}); // Não deve acontecer devido ao protectRoute
        if (user.balance < plan.price_mt) return res.status(400).json({m:"Saldo insuficiente para adquirir este plano."});

        // Verificar limite de aquisições do plano (maxInvestmentsPerUser)
        if (plan.maxInvestmentsPerUser > 0) {
            const existingInvestmentsCount = await UserInvestment.countDocuments({ user: user._id, plan: plan._id });
            if (existingInvestmentsCount >= plan.maxInvestmentsPerUser) {
                return res.status(400).json({m: `Você já atingiu o limite de ${plan.maxInvestmentsPerUser} aquisição(ões) para este plano.`});
            }
        }
        // Opcional: Verificar se já existe um plano ATIVO do mesmo tipo (se não quiser permitir múltiplos ativos do mesmo plano)
        // const activeInvestmentOfThisPlan = await UserInvestment.findOne({ user: user._id, plan: plan._id, isActive: true });
        // if (activeInvestmentOfThisPlan) return res.status(400).json({m: "Você já possui um investimento ativo deste plano."});


        const balanceBefore = user.balance;
        user.balance -= plan.price_mt;
        
        const newInvestment = new UserInvestment({
            user: user._id,
            plan: plan._id,
            planSnapshot: { // Salva uma cópia dos detalhes do plano no momento da compra
                name: plan.name,
                price_mt: plan.price_mt,
                daily_profit_mt: plan.daily_profit_mt,
                duration_days: plan.duration_days
            }
            // startDate é default: Date.now(), endDate e nextCollectionAvailableAt são definidos no pre-save
        });
        await newInvestment.save(); // Salva o investimento primeiro para ter o _id
        await createTransactionEntry(user._id, 'plan_purchase', -plan.price_mt, 
            `Compra do Plano: ${plan.name}`, 'completed', balanceBefore, user.balance, 
            {relatedInvestment: newInvestment._id});

        // Lógica de Bônus de Indicação pela Compra do Plano
        if (user.referredBy) {
            const referrer = await User.findById(user.referredBy);
            const systemSettings = await getOrInitializeSystemSettings();
            if (referrer && systemSettings.isReferralSystemActive && systemSettings.referralPlanPurchaseBonusPercentage > 0) {
                const bonusAmount = plan.price_mt * systemSettings.referralPlanPurchaseBonusPercentage;
                if (bonusAmount > 0) {
                    const referrerBalanceBefore = referrer.balance;
                    referrer.balance += bonusAmount;
                    await referrer.save();
                    await createTransactionEntry(referrer._id, 'referral_bonus_plan', bonusAmount, 
                        `Bônus por indicação (compra de plano por ${user.name})`, 'completed', 
                        referrerBalanceBefore, referrer.balance, {relatedUser: user._id});
                    await createUserNotification(referrer._id, 'Você Ganhou um Bônus de Indicação!', 
                        `Você recebeu ${bonusAmount.toFixed(2)} MT porque ${user.name} adquiriu o plano ${plan.name}.`, 'success', '/referrals');
                }
            }
        }
        await user.save(); // Salva o usuário após debitar o saldo e possivelmente após o referente ser salvo (se houver)
        await createUserNotification(user._id, 'Investimento Realizado com Sucesso!', 
            `Você investiu no plano ${plan.name}. Acompanhe seus lucros!`, 'success', '/investments/my-history');
        
        res.status(201).json({ m: "Investimento realizado com sucesso!", investment: newInvestment });
    } catch (error) {
        console.error("Erro ao realizar investimento:", error);
        res.status(500).json({ m: "Erro no servidor ao tentar realizar o investimento." });
    }
});
investmentRouter.get('/my-active', async (req, res) => {
    try {
        await updateUncollectedProfits(req.user.id); // Atualiza lucros antes de buscar
        const activeInvestment = await UserInvestment.findOne({ user: req.user.id, isActive: true })
            .populate('plan', 'name icon_bs_class hashrate_mhs'); // Popula alguns detalhes do plano original
        
        if(!activeInvestment) return res.json(null); // Retorna null explicitamente se não houver plano ativo
        res.json(activeInvestment);
    } catch (error) {
        console.error("Erro ao buscar investimento ativo:", error);
        res.status(500).json({ m: "Erro ao buscar seu investimento ativo." });
    }
});
investmentRouter.post('/collect-profit', async (req, res) => {
    try {
        const userId = req.user.id;
        await updateUncollectedProfits(userId); // Garante que uncollectedProfit está atualizado

        const investment = await UserInvestment.findOne({user: userId, isActive: true});
        if (!investment) return res.status(404).json({m: "Nenhum investimento ativo encontrado para coletar lucros."});

        const now = new Date();
        if (investment.nextCollectionAvailableAt && now < investment.nextCollectionAvailableAt) {
            const timeLeftMs = investment.nextCollectionAvailableAt.getTime() - now.getTime();
            const hoursLeft = Math.floor(timeLeftMs / (1000 * 60 * 60));
            const minutesLeft = Math.floor((timeLeftMs % (1000 * 60 * 60)) / (1000 * 60));
            return res.status(400).json({m: `A próxima coleta de lucros estará disponível em aproximadamente ${hoursLeft}h ${minutesLeft}m.`});
        }
        
        if (investment.uncollectedProfit <= 0) return res.status(400).json({m: "Não há lucros não coletados para este investimento."});

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({m: "Usuário não encontrado."}); // Improvável se passou pelo protectRoute

        const amountToCollect = parseFloat(investment.uncollectedProfit.toFixed(2));
        const balanceBeforeCollection = user.balance;
        user.balance += amountToCollect;
        
        investment.totalProfitCollected += amountToCollect;
        investment.uncollectedProfit = 0; // Zera o lucro não coletado
        investment.lastCollectedAt = now; // Registra a data da última coleta

        // Calcula a próxima data de coleta (dia seguinte, na hora configurada)
        let nextCollectionDateTimeLocal = new Date(now);
        nextCollectionDateTimeLocal.setHours(nextCollectionDateTimeLocal.getHours() + TIMEZONE_OFFSET_HOURS); // Ajusta para o fuso local
        nextCollectionDateTimeLocal.setDate(nextCollectionDateTimeLocal.getDate() + 1); // Próximo dia
        nextCollectionDateTimeLocal.setHours(PROFIT_COLLECTION_START_HOUR, 0, 0, 0); // Hora de coleta no fuso local
        // Converte de volta para UTC para salvar no banco
        investment.nextCollectionAvailableAt = new Date(Date.UTC(
            nextCollectionDateTimeLocal.getUTCFullYear(), 
            nextCollectionDateTimeLocal.getUTCMonth(), 
            nextCollectionDateTimeLocal.getUTCDate(), 
            nextCollectionDateTimeLocal.getUTCHours() - TIMEZONE_OFFSET_HOURS, // Converte a hora local de volta para UTC
            0,0,0
        ));

        await createTransactionEntry(user._id, 'profit_collection', amountToCollect, 
            `Coleta de lucros do plano: ${investment.planSnapshot.name}`, 'completed', 
            balanceBeforeCollection, user.balance, {relatedInvestment: investment._id});

        // Lógica de Bônus de Indicação pela Coleta de Lucro
        if (user.referredBy) {
            const referrer = await User.findById(user.referredBy);
            const systemSettings = await getOrInitializeSystemSettings();
            if (referrer && systemSettings.isReferralSystemActive && systemSettings.referralDailyProfitBonusPercentage > 0) {
                const dailyProfitBonus = parseFloat((amountToCollect * systemSettings.referralDailyProfitBonusPercentage).toFixed(2));
                if (dailyProfitBonus > 0) {
                    const referrerBalanceBefore = referrer.balance;
                    referrer.balance += dailyProfitBonus;
                    await referrer.save();
                    await createTransactionEntry(referrer._id, 'referral_bonus_profit', dailyProfitBonus, 
                        `Bônus por coleta de lucros de ${user.name}`, 'completed', 
                        referrerBalanceBefore, referrer.balance, {relatedUser: user._id});
                    await createUserNotification(referrer._id, 'Você Ganhou um Bônus de Indicação!', 
                        `Você recebeu ${dailyProfitBonus.toFixed(2)} MT porque ${user.name} coletou lucros.`, 'success', '/referrals');
                }
            }
        }
        
        await user.save();
        await investment.save();
        await createUserNotification(user._id, 'Lucros Coletados com Sucesso!', 
            `${amountToCollect.toFixed(2)} MT foram adicionados ao seu saldo. Saldo atual: ${user.balance.toFixed(2)} MT.`, 'success', '/wallet');

        res.json({ m: `${amountToCollect.toFixed(2)} MT coletados com sucesso!`, newBalance: user.balance.toFixed(2) });
    } catch(error) {
        console.error("Erro ao coletar lucros:", error);
        res.status(500).json({m:"Erro no servidor ao tentar coletar lucros."});
    }
});
investmentRouter.get('/my-history', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        const query = { user: req.user.id };

        const investments = await UserInvestment.find(query)
            .populate('plan', 'name icon_bs_class') // Popula alguns detalhes do plano original
            .sort({ startDate: -1 }) // Mais recentes primeiro
            .skip(skip)
            .limit(limit);
        const totalInvestments = await UserInvestment.countDocuments(query);
        res.json({ investments: investments, currentPage: page, totalPages: Math.ceil(totalInvestments / limit), totalCount: totalInvestments });
    } catch (error) {
        console.error("Erro ao buscar histórico de investimentos:", error);
        res.status(500).json({ m: "Erro ao buscar seu histórico de investimentos." });
    }
});
app.use('/api/investments', protectRoute, investmentRouter);


// --- ROTAS DE BLOG (/api/blog) ---
const blogRouter = express.Router();
blogRouter.post('/', protectRoute, adminOnly, async (req, res) => {
    try {
        const { title, content, slug, snippet, tags, isPublished, coverImageUrl } = req.body;
        if (!title || !content) return res.status(400).json({m: "Título e conteúdo são obrigatórios para o post."});
        
        let postSlug = slug;
        if (!postSlug) { // Gera slug a partir do título se não fornecido
            postSlug = title.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '');
        }
        const existingSlug = await BlogPost.findOne({ slug: postSlug });
        if (existingSlug) return res.status(400).json({m: "Este slug já está em uso. Escolha outro."});

        const newPost = new BlogPost({ 
            title, content, slug: postSlug, 
            snippet: snippet || (content.length > 250 ? content.substring(0, 250) + '...' : content),
            tags: tags || [],
            isPublished: isPublished === true,
            coverImageUrl,
            author: req.user.id // ID do admin logado
        });
        await newPost.save();
        res.status(201).json({ m: "Post do blog criado com sucesso!", post: newPost });
    } catch (error) {
        console.error("Erro ao criar post do blog:", error);
        if (error.code === 11000) return res.status(400).json({m: "Um post com este título ou slug já existe."});
        if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)});
        res.status(500).json({ m: "Erro no servidor ao criar post." });
    }
});
blogRouter.get('/', async (req, res) => { // Rota pública para listar posts publicados
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        const tagFilter = req.query.tag;
        const searchQuery = req.query.search;

        let query = { isPublished: true };
        if (tagFilter) query.tags = tagFilter.trim().toLowerCase();
        if (searchQuery) query.title = { $regex: searchQuery, $options: 'i' }; // Busca case-insensitive no título

        const posts = await BlogPost.find(query)
            .populate('author', 'name') // Mostra nome do autor
            .sort({ createdAt: -1 }) // Mais recentes primeiro
            .skip(skip)
            .limit(limit)
            .select('title slug snippet tags createdAt coverImageUrl author views'); // Campos selecionados para a listagem
        
        const totalPosts = await BlogPost.countDocuments(query);
        res.json({ posts: posts, currentPage: page, totalPages: Math.ceil(totalPosts / limit), totalCount: totalPosts });
    } catch (error) {
        console.error("Erro ao buscar posts do blog (público):", error);
        res.status(500).json({ m: "Erro ao buscar posts do blog." });
    }
});
blogRouter.get('/all', protectRoute, adminOnly, async (req, res) => { // Rota admin para listar TODOS os posts (publicados ou não)
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20; // Admin pode ver mais
        const skip = (page - 1) * limit;
        const { isPublished, search } = req.query;

        let query = {};
        if (isPublished !== undefined) query.isPublished = (isPublished === 'true');
        if (search) query.title = { $regex: search, $options: 'i' };

        const posts = await BlogPost.find(query).populate('author', 'name').sort({ createdAt: -1 }).skip(skip).limit(limit);
        const totalPosts = await BlogPost.countDocuments(query);
        res.json({ posts: posts, currentPage: page, totalPages: Math.ceil(totalPosts / limit), totalCount: totalPosts });
    } catch (error) {
        console.error("Erro ao buscar todos os posts (admin):", error);
        res.status(500).json({ m: "Erro ao buscar posts." });
    }
});
blogRouter.get('/slug/:slug', async (req, res) => { // Rota pública para ver um post pelo slug
    try {
        const post = await BlogPost.findOneAndUpdate(
            { slug: req.params.slug.toLowerCase(), isPublished: true },
            { $inc: { views: 1 } }, // Incrementa visualizações
            { new: true } // Retorna o documento atualizado
        ).populate('author', 'name');
        
        if (!post) return res.status(404).json({ m: "Post do blog não encontrado ou não publicado." });
        res.json(post);
    } catch (error) {
        console.error("Erro ao buscar post do blog por slug:", error);
        res.status(500).json({ m: "Erro ao buscar post." });
    }
});
blogRouter.get('/id/:id', protectRoute, adminOnly, async (req, res) => { // Rota admin para ver post por ID (publicado ou não)
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de post inválido."});
        const post = await BlogPost.findById(req.params.id).populate('author', 'name');
        if (!post) return res.status(404).json({m: "Post não encontrado."});
        res.json(post);
    } catch (error) {
        console.error("Erro ao buscar post por ID (admin):", error);
        res.status(500).json({ m: "Erro ao buscar post." });
    }
});
blogRouter.put('/:id', protectRoute, adminOnly, async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de post inválido."});
        const updateData = { ...req.body };

        if (updateData.slug) { // Se um novo slug for fornecido, normaliza e verifica unicidade
            const newSlug = updateData.slug.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '');
            const existingPostWithSlug = await BlogPost.findOne({ slug: newSlug, _id: { $ne: req.params.id } });
            if (existingPostWithSlug) return res.status(400).json({m: "Este slug já está em uso por outro post."});
            updateData.slug = newSlug;
        } else if (updateData.title && !updateData.slug) { // Se título mudou e slug não foi fornecido, gera novo slug
             updateData.slug = updateData.title.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '');
        }
        
        // Atualiza snippet se o conteúdo mudou e snippet não foi explicitamente fornecido
        if (updateData.content && updateData.snippet === undefined) {
            updateData.snippet = updateData.content.substring(0, 250) + (updateData.content.length > 250 ? '...' : '');
        }

        updateData.updatedAt = Date.now();
        const updatedPost = await BlogPost.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true, runValidators: true });
        if (!updatedPost) return res.status(404).json({m: "Post não encontrado para atualização."});
        res.json({ m: "Post do blog atualizado com sucesso!", post: updatedPost });
    } catch (error) {
        console.error("Erro ao atualizar post do blog:", error);
        if (error.code === 11000) return res.status(400).json({m: "Um post com este título ou slug já existe."});
        if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)});
        res.status(500).json({ m: "Erro no servidor ao atualizar post." });
    }
});
blogRouter.delete('/:id', protectRoute, adminOnly, async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de post inválido."});
        const deletedPost = await BlogPost.findByIdAndDelete(req.params.id);
        if (!deletedPost) return res.status(404).json({m: "Post não encontrado para deleção."});
        res.json({ m: "Post do blog deletado com sucesso." });
    } catch (error) {
        console.error("Erro ao deletar post do blog:", error);
        res.status(500).json({ m: "Erro no servidor ao deletar post." });
    }
});
app.use('/api/blog', blogRouter);


// --- ROTAS DE PROMOÇÕES (/api/promotions) ---
const promotionRouter = express.Router();
promotionRouter.post('/', protectRoute, adminOnly, async (req, res) => {
    try {
        const { title, description } = req.body; // Campos mínimos
        if (!title || !description) return res.status(400).json({m: "Título e descrição são obrigatórios para a promoção."});
        
        // Converte datas se fornecidas, senão usa defaults ou null
        const newPromotionData = {
            ...req.body,
            isActive: req.body.isActive === true, // Garante booleano
            startDate: req.body.startDate ? new Date(req.body.startDate) : Date.now(),
            endDate: req.body.endDate ? new Date(req.body.endDate) : null,
            countdownTargetDate: req.body.countdownTargetDate ? new Date(req.body.countdownTargetDate) : null
        };
        const newPromotion = new Promotion(newPromotionData);
        await newPromotion.save();
        res.status(201).json({ m: "Promoção criada com sucesso!", promotion: newPromotion });
    } catch (error) {
        console.error("Erro ao criar promoção:", error);
        if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)});
        res.status(500).json({ m: "Erro no servidor ao criar promoção." });
    }
});
promotionRouter.get('/active', async (req, res) => { // Rota pública para promoções ativas (incluindo tipo 'blog')
    try {
        const now = new Date();
        // Busca promoções ativas, incluindo aquelas sem data de fim ou cuja data de fim ainda não passou
        // E que já começaram ou não têm data de início definida
        const activePromotions = await Promotion.find({
            isActive: true,
            $or: [
                { startDate: { $lte: now } },
                { startDate: null }
            ],
            $or: [ // Modificado para $and com $or interno para lógica correta de endDate
                { endDate: { $gte: now } },
                { endDate: null }
            ]
        }).sort({ priority: -1, createdAt: -1 }); // Ordena por prioridade e depois por data de criação
        res.json(activePromotions);
    } catch (error) {
        console.error("Erro ao buscar promoções ativas:", error);
        res.status(500).json({ m: "Erro ao buscar promoções ativas." });
    }
});
promotionRouter.get('/type/:typeName', async (req, res) => { // Rota para buscar promoções ativas por tipo
    try {
      const typeName = req.params.typeName.toLowerCase();
      const now = new Date();
      const activePromotionsByType = await Promotion.find({
        type: typeName,
        isActive: true,
        $or: [ { startDate: { $lte: now } }, { startDate: null } ],
        $or: [ { endDate: { $gte: now } }, { endDate: null } ]
      }).sort({ priority: -1, createdAt: -1 });

      if (!activePromotionsByType || activePromotionsByType.length === 0) {
        return res.status(200).json([]); // Retorna array vazio se nada encontrado
      }
      res.json(activePromotionsByType);
    } catch (error) {
      console.error(`Erro ao buscar promoções ativas por tipo (${req.params.typeName}):`, error);
      res.status(500).json({ m: "Erro ao buscar promoções por tipo." });
    }
});
promotionRouter.get('/all', protectRoute, adminOnly, async (req, res) => { // Rota admin para todas as promoções
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        const isActiveFilter = req.query.isActive; // 'true', 'false', ou undefined

        let query = {};
        if (isActiveFilter !== undefined) {
            query.isActive = (isActiveFilter === 'true');
        }
        const promotions = await Promotion.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit);
        const totalPromotions = await Promotion.countDocuments(query);
        res.json({ promotions: promotions, currentPage: page, totalPages: Math.ceil(totalPromotions / limit), totalCount: totalPromotions });
    } catch (error) {
        console.error("Erro ao buscar todas as promoções (admin):", error);
        res.status(500).json({ m: "Erro ao buscar promoções." });
    }
});
promotionRouter.get('/:id', protectRoute, adminOnly, async (req, res) => { // Admin: buscar uma promoção por ID
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de promoção inválido."});
        const promotion = await Promotion.findById(req.params.id);
        if (!promotion) return res.status(404).json({m: "Promoção não encontrada."});
        res.json(promotion);
    } catch (error) {
        console.error("Erro ao buscar promoção por ID (admin):", error);
        res.status(500).json({ m: "Erro ao buscar promoção." });
    }
});
promotionRouter.put('/:id', protectRoute, adminOnly, async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de promoção inválido."});
        const updateData = { ...req.body };
        // Normaliza isActive para booleano
        if (updateData.isActive !== undefined) {
            updateData.isActive = (updateData.isActive === true || updateData.isActive === 'true');
        }
        // Converte datas string para Date objects, ou null se string vazia
        if (updateData.startDate) updateData.startDate = new Date(updateData.startDate);
        if (updateData.endDate) updateData.endDate = new Date(updateData.endDate);
        else if (updateData.endDate === '') updateData.endDate = null; 
        if (updateData.countdownTargetDate) updateData.countdownTargetDate = new Date(updateData.countdownTargetDate);
        else if (updateData.countdownTargetDate === '') updateData.countdownTargetDate = null;

        const updatedPromotion = await Promotion.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true, runValidators: true });
        if (!updatedPromotion) return res.status(404).json({m: "Promoção não encontrada para atualização."});
        res.json({ m: "Promoção atualizada com sucesso!", promotion: updatedPromotion });
    } catch (error) {
        console.error("Erro ao atualizar promoção:", error);
        if (error.name === 'ValidationError') return res.status(400).json({m: "Erro de validação.", e: Object.values(error.errors).map(val => val.message)});
        res.status(500).json({ m: "Erro no servidor ao atualizar promoção." });
    }
});
promotionRouter.delete('/:id', protectRoute, adminOnly, async (req, res) => {
    try {
        if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({m:"ID de promoção inválido."});
        const deletedPromotion = await Promotion.findByIdAndDelete(req.params.id);
        if (!deletedPromotion) return res.status(404).json({m: "Promoção não encontrada para deleção."});
        res.json({ m: "Promoção deletada com sucesso." });
    } catch (error) {
        console.error("Erro ao deletar promoção:", error);
        res.status(500).json({ m: "Erro no servidor ao deletar promoção." });
    }
});
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
            console.log(`Servidor Backend Foundry Invest rodando na Porta ${PORT}`); // Nome atualizado
            console.log('Todas as rotas e configurações carregadas. Backend pronto!');
        });
    } catch (error) {
        console.error('Falha Crítica ao Iniciar Servidor:', error.message);
        process.exit(1);
    }
}

// Garante que o servidor só inicie se este arquivo for executado diretamente
if (require.main === module) { 
  startServer();
}

// module.exports = app; // Descomente para testes de integração se necessário