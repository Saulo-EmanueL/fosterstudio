/* =========================================================
   STUDIO DE TELAS — servidor
   - Login protegendo o site inteiro (senha só no servidor)
   - Biblioteca de modelos compartilhada na nuvem (MongoDB)
   - Sessão por cookie assinado (à prova de adulteração)
   ========================================================= */
'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

/* ---------- configuração (tudo por variável de ambiente) ---------- */
const PORT           = process.env.PORT || 3000;
const ADMIN_USER     = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'mercenario';
const MONGODB_URI    = process.env.MONGODB_URI || '';
const DB_NAME        = process.env.DB_NAME || 'studio_telas';
// Se não definir SESSION_SECRET, gera um por inicialização (derruba sessões a cada deploy).
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSAO_HORAS   = 12;

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // Render fica atrás de proxy — necessário pro IP e cookie secure
app.use(express.json({ limit: '12mb' }));      // projetos com imagens base64
app.use(cookieParser());

/* =========================================================
   SESSÃO ASSINADA  (HMAC — não dá pra forjar sem o segredo)
   ========================================================= */
function assinar(dados) {
    return crypto.createHmac('sha256', SESSION_SECRET).update(dados).digest('base64url');
}
function criarToken() {
    const exp = Date.now() + SESSAO_HORAS * 3600 * 1000;
    const corpo = 'v1.' + exp;
    return corpo + '.' + assinar(corpo);
}
function tokenValido(token) {
    if (!token || typeof token !== 'string') return false;
    const partes = token.split('.');
    if (partes.length !== 3) return false;
    const corpo = partes[0] + '.' + partes[1];
    const esperado = assinar(corpo);
    // comparação em tempo constante (evita ataque de timing)
    const a = Buffer.from(partes[2]);
    const b = Buffer.from(esperado);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
    const exp = parseInt(partes[1], 10);
    return Number.isFinite(exp) && Date.now() < exp;
}
function setCookieSessao(res) {
    res.cookie('sessao', criarToken(), {
        httpOnly: true,                 // JS do navegador não enxerga o cookie
        sameSite: 'strict',             // não vaza pra outros sites
        secure: process.env.NODE_ENV === 'production',
        maxAge: SESSAO_HORAS * 3600 * 1000
    });
}
function autenticado(req) {
    return tokenValido(req.cookies && req.cookies.sessao);
}
function exigirLogin(req, res, next) {
    if (autenticado(req)) return next();
    res.status(401).json({ erro: 'nao_autenticado' });
}

/* =========================================================
   LIMITE DE TENTATIVAS DE LOGIN (por IP)
   ========================================================= */
const tentativas = new Map(); // ip -> { n, ate }
function bloqueado(ip) {
    const t = tentativas.get(ip);
    return t && t.ate > Date.now();
}
function registrarFalha(ip) {
    const t = tentativas.get(ip) || { n: 0, ate: 0 };
    t.n++;
    if (t.n >= 6) { t.ate = Date.now() + 5 * 60 * 1000; t.n = 0; } // trava 5 min após 6 erros
    tentativas.set(ip, t);
}
function limparFalhas(ip) { tentativas.delete(ip); }

function comparaSegura(a, b) {
    const ba = Buffer.from(String(a));
    const bb = Buffer.from(String(b));
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
}

/* =========================================================
   ARMAZENAMENTO  (MongoDB, com fallback pra arquivo local)
   ========================================================= */
let colecao = null;          // MongoDB
let usandoArquivo = false;   // fallback
const ARQ = path.join(__dirname, 'data', 'modelos.json');

async function iniciarBanco() {
    if (MONGODB_URI) {
        const { MongoClient } = require('mongodb');
        const client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
        await client.connect();
        colecao = client.db(DB_NAME).collection('modelos');
        await colecao.createIndex({ criadoEm: -1 });
        console.log('[banco] MongoDB conectado');
    } else {
        usandoArquivo = true;
        fs.mkdirSync(path.dirname(ARQ), { recursive: true });
        if (!fs.existsSync(ARQ)) fs.writeFileSync(ARQ, '[]');
        console.log('[banco] SEM MONGODB_URI — usando arquivo local (não persiste no Render grátis)');
    }
}
function lerArquivo() { try { return JSON.parse(fs.readFileSync(ARQ, 'utf8')); } catch (e) { return []; } }
function salvarArquivo(lista) { fs.writeFileSync(ARQ, JSON.stringify(lista)); }

async function listarModelos() {
    if (usandoArquivo) return lerArquivo().sort((a, b) => b.criadoEm - a.criadoEm);
    return colecao.find({}, { projection: { _id: 0 } }).sort({ criadoEm: -1 }).toArray();
}
async function inserirModelo(doc) {
    if (usandoArquivo) { const l = lerArquivo(); l.push(doc); salvarArquivo(l); return; }
    await colecao.insertOne(doc);
}
async function apagarModelo(id) {
    if (usandoArquivo) { salvarArquivo(lerArquivo().filter(m => m.id !== id)); return; }
    await colecao.deleteOne({ id: id });
}

/* =========================================================
   ROTAS DE AUTENTICAÇÃO
   ========================================================= */
app.post('/api/login', (req, res) => {
    const ip = req.ip || 'x';
    if (bloqueado(ip)) return res.status(429).json({ erro: 'muitas_tentativas' });

    const { usuario, senha } = req.body || {};
    const okUser = comparaSegura(usuario || '', ADMIN_USER);
    const okSenha = comparaSegura(senha || '', ADMIN_PASSWORD);
    if (okUser && okSenha) {
        limparFalhas(ip);
        setCookieSessao(res);
        return res.json({ ok: true });
    }
    registrarFalha(ip);
    res.status(401).json({ erro: 'credenciais_invalidas' });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('sessao');
    res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
    res.json({ autenticado: autenticado(req) });
});

/* =========================================================
   ROTAS DA BIBLIOTECA (todas exigem login)
   ========================================================= */
app.get('/api/modelos', exigirLogin, async (req, res) => {
    try { res.json(await listarModelos()); }
    catch (e) { res.status(500).json({ erro: 'falha_ao_listar' }); }
});

app.post('/api/modelos', exigirLogin, async (req, res) => {
    try {
        const { nome, dados } = req.body || {};
        if (!nome || !dados || typeof dados !== 'object') {
            return res.status(400).json({ erro: 'dados_invalidos' });
        }
        const doc = {
            id: crypto.randomUUID(),
            nome: String(nome).slice(0, 80),
            desc: String((req.body.desc || '')).slice(0, 120),
            dados: dados,
            criadoEm: Date.now()
        };
        await inserirModelo(doc);
        res.json({ ok: true, id: doc.id });
    } catch (e) { res.status(500).json({ erro: 'falha_ao_salvar' }); }
});

app.delete('/api/modelos/:id', exigirLogin, async (req, res) => {
    try { await apagarModelo(req.params.id); res.json({ ok: true }); }
    catch (e) { res.status(500).json({ erro: 'falha_ao_apagar' }); }
});

/* =========================================================
   PÁGINAS  (o editor só é servido pra quem está logado)
   ========================================================= */
app.get('/', (req, res) => {
    if (autenticado(req)) res.sendFile(path.join(__dirname, 'public', 'index.html'));
    else res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// bloqueia acesso direto ao index.html sem sessão
app.get('/index.html', (req, res) => {
    if (autenticado(req)) res.sendFile(path.join(__dirname, 'public', 'index.html'));
    else res.redirect('/');
});

app.get('/login', (req, res) => res.redirect('/'));

// arquivos estáticos permitidos sem login (só a tela de login e favicon)
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.get('/saude', (req, res) => res.json({ ok: true, banco: usandoArquivo ? 'arquivo' : 'mongodb' }));

/* =========================================================
   START
   ========================================================= */
iniciarBanco()
    .then(() => app.listen(PORT, () => console.log('[servidor] rodando na porta ' + PORT)))
    .catch(err => { console.error('Falha ao iniciar o banco:', err.message); process.exit(1); });
