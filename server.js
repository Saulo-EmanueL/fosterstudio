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
// Código secreto do DONO (só quem tem pode excluir modelos). Ative visitando /dono/SEUCODIGO
const OWNER_KEY      = process.env.OWNER_KEY || 'dono-renova-2026';
const DONO_DIAS      = 365;

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

/* ---------- modo DONO (cookie próprio, assinado) ---------- */
function criarTokenDono() {
    var corpo = 'd1.' + (Date.now() + DONO_DIAS * 86400000);
    return corpo + '.' + assinar(corpo);
}
function donoValido(req) {
    var token = req.cookies && req.cookies.dono;
    if (!token) return false;
    var partes = token.split('.');
    if (partes.length !== 3 || partes[0] !== 'd1') return false;
    var corpo = partes[0] + '.' + partes[1];
    var a = Buffer.from(partes[2]), b = Buffer.from(assinar(corpo));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
    var exp = parseInt(partes[1], 10);
    return Number.isFinite(exp) && Date.now() < exp;
}
function exigirDono(req, res, next) {
    if (autenticado(req) && donoValido(req)) return next();
    res.status(403).json({ erro: 'somente_dono' });
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
let colecao = null;          // modelos (MongoDB)
let colecaoImg = null;       // imagens (MongoDB)
let usandoArquivo = false;   // fallback
const ARQ = path.join(__dirname, 'data', 'modelos.json');
const ARQ_IMG = path.join(__dirname, 'data', 'imagens.json');

async function iniciarBanco() {
    if (MONGODB_URI) {
        const { MongoClient } = require('mongodb');
        const client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
        await client.connect();
        const db = client.db(DB_NAME);
        colecao = db.collection('modelos');
        colecaoImg = db.collection('imagens');
        await colecao.createIndex({ criadoEm: -1 });
        await colecaoImg.createIndex({ criadoEm: -1 });
        console.log('[banco] MongoDB conectado');
    } else {
        usandoArquivo = true;
        fs.mkdirSync(path.dirname(ARQ), { recursive: true });
        if (!fs.existsSync(ARQ)) fs.writeFileSync(ARQ, '[]');
        if (!fs.existsSync(ARQ_IMG)) fs.writeFileSync(ARQ_IMG, '[]');
        console.log('[banco] SEM MONGODB_URI — usando arquivo local (não persiste no Render grátis)');
    }
}
function lerArq(a) { try { return JSON.parse(fs.readFileSync(a, 'utf8')); } catch (e) { return []; } }
function salvarArq(a, lista) { fs.writeFileSync(a, JSON.stringify(lista)); }

async function listarModelos() {
    if (usandoArquivo) return lerArq(ARQ).sort((a, b) => b.criadoEm - a.criadoEm);
    return colecao.find({}, { projection: { _id: 0 } }).sort({ criadoEm: -1 }).toArray();
}
async function inserirModelo(doc) {
    if (usandoArquivo) { const l = lerArq(ARQ); l.push(doc); salvarArq(ARQ, l); return; }
    await colecao.insertOne(doc);
}
async function apagarModelo(id) {
    if (usandoArquivo) { salvarArq(ARQ, lerArq(ARQ).filter(m => m.id !== id)); return; }
    await colecao.deleteOne({ id: id });
}

async function listarImagens() {
    if (usandoArquivo) return lerArq(ARQ_IMG).sort((a, b) => b.criadoEm - a.criadoEm);
    return colecaoImg.find({}, { projection: { _id: 0 } }).sort({ criadoEm: -1 }).toArray();
}
async function inserirImagem(doc) {
    if (usandoArquivo) { const l = lerArq(ARQ_IMG); l.push(doc); salvarArq(ARQ_IMG, l); return; }
    await colecaoImg.insertOne(doc);
}
async function apagarImagem(id) {
    if (usandoArquivo) { salvarArq(ARQ_IMG, lerArq(ARQ_IMG).filter(m => m.id !== id)); return; }
    await colecaoImg.deleteOne({ id: id });
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
    res.json({ autenticado: autenticado(req), dono: autenticado(req) && donoValido(req) });
});

/* ativa o modo dono: visite /dono/SEUCODIGO uma vez */
app.get('/dono/:chave', (req, res) => {
    if (comparaSegura(req.params.chave || '', OWNER_KEY)) {
        res.cookie('dono', criarTokenDono(), {
            httpOnly: true, sameSite: 'strict',
            secure: process.env.NODE_ENV === 'production',
            maxAge: DONO_DIAS * 86400000
        });
        return res.redirect('/');
    }
    res.status(404).send('Não encontrado');
});

/* sair do modo dono */
app.get('/dono-sair', (req, res) => { res.clearCookie('dono'); res.redirect('/'); });

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

app.delete('/api/modelos/:id', exigirDono, async (req, res) => {
    try { await apagarModelo(req.params.id); res.json({ ok: true }); }
    catch (e) { res.status(500).json({ erro: 'falha_ao_apagar' }); }
});

/* ---------- biblioteca de imagens (ver: qualquer logado; add/excluir: só dono) ---------- */
app.get('/api/imagens', exigirLogin, async (req, res) => {
    try { res.json(await listarImagens()); }
    catch (e) { res.status(500).json({ erro: 'falha_ao_listar' }); }
});
app.post('/api/imagens', exigirDono, async (req, res) => {
    try {
        const { nome, src } = req.body || {};
        if (!src || typeof src !== 'string') return res.status(400).json({ erro: 'sem_imagem' });
        const doc = {
            id: crypto.randomUUID(),
            nome: String(nome || 'imagem').slice(0, 60),
            src: src.slice(0, 6 * 1024 * 1024),   // teto de segurança
            criadoEm: Date.now()
        };
        await inserirImagem(doc);
        res.json({ ok: true, id: doc.id });
    } catch (e) { res.status(500).json({ erro: 'falha_ao_salvar' }); }
});
app.delete('/api/imagens/:id', exigirDono, async (req, res) => {
    try { await apagarImagem(req.params.id); res.json({ ok: true }); }
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
