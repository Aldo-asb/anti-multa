// Servidor de Produção Full-Stack: v16.0
// Anti-Multa Goiânia — Backend Principal
require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = 'asbautomacao@gmail.com';

const pool = new Pool({
    host: 'aws-1-sa-east-1.pooler.supabase.com',
    port: 5432, database: 'postgres',
    user: 'postgres.mcpzdtewuqmbxxlrttfc',
    password: process.env.DB_PASSWORD,
    ssl: { rejectUnauthorized: false },
    max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000,
});

async function inicializarBancoDeDados() {
    try {
        const client = await pool.connect();
        console.log('✅ Conexão com o banco estabelecida!');
        client.release();

        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id         SERIAL PRIMARY KEY,
                nome       VARCHAR(100) NOT NULL,
                email      VARCHAR(100) UNIQUE NOT NULL,
                telefone   VARCHAR(20),
                senha_hash VARCHAR(255) NOT NULL,
                pin_hash   VARCHAR(255) NOT NULL,
                is_admin   BOOLEAN DEFAULT FALSE,
                ativo      BOOLEAN DEFAULT FALSE,
                criado_em  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS telefone VARCHAR(20);`);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;`);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ativo BOOLEAN DEFAULT FALSE;`);
        // Admin sempre ativo
        await pool.query(`UPDATE users SET is_admin = TRUE, ativo = TRUE WHERE email = $1`, [ADMIN_EMAIL]);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS radares (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                local VARCHAR(255) NOT NULL,
                lat DOUBLE PRECISION NOT NULL,
                lon DOUBLE PRECISION NOT NULL,
                velocidade INTEGER NOT NULL,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS limites_via (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                descricao VARCHAR(255) NOT NULL,
                lat DOUBLE PRECISION NOT NULL,
                lon DOUBLE PRECISION NOT NULL,
                velocidade INTEGER NOT NULL,
                validado BOOLEAN DEFAULT FALSE,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS alertas (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                tipo VARCHAR(50) NOT NULL,
                descricao VARCHAR(255) NOT NULL,
                lat DOUBLE PRECISION NOT NULL,
                lon DOUBLE PRECISION NOT NULL,
                expira_em TIMESTAMP NOT NULL,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log('=== BANCO DE DADOS POSTGRESQL SINCRONIZADO COM SUCESSO ===');
    } catch (err) {
        console.error('❌ ERRO CRÍTICO:', err.message);
        process.exit(1);
    }
}
inicializarBancoDeDados();

// MIDDLEWARES
function verificarTokenJWT(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Token não fornecido.' });
    try { req.user = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET); next(); }
    catch { res.status(400).json({ error: 'Token inválido.' }); }
}
function verificarAdmin(req, res, next) {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Acesso restrito ao administrador.' });
    next();
}
function verificarAtivo(req, res, next) {
    if (!req.user.ativo && !req.user.is_admin)
        return res.status(403).json({ error: 'CONTA_INATIVA', msg: 'Sua conta aguarda aprovação do administrador.' });
    next();
}

// =====================================================================================
// AUTH
// =====================================================================================
app.post('/api/auth/register', async (req, res) => {
    const { nome, email, telefone, senha, pin } = req.body;
    try {
        if (!nome || !email || !senha || !pin)
            return res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });
        const senhaHash = await bcrypt.hash(senha, 10);
        const pinHash   = await bcrypt.hash(pin.toString(), 10);
        const isAdmin   = email === ADMIN_EMAIL;
        const ativo     = isAdmin; // Admin ativo por padrão, demais aguardam aprovação
        const novo = await pool.query(
            'INSERT INTO users (nome, email, telefone, senha_hash, pin_hash, is_admin, ativo) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, nome, email, is_admin, ativo',
            [nome, email, telefone || null, senhaHash, pinHash, isAdmin, ativo]
        );
        if (!ativo) {
            return res.json({ pendente: true, msg: 'Cadastro realizado! Aguarde a aprovação do administrador para acessar o app.' });
        }
        const token = jwt.sign({ id: novo.rows[0].id, is_admin: isAdmin, ativo: true }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user: novo.rows[0] });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'E-mail já cadastrado.' });
        res.status(500).json({ error: 'Erro no cadastro.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, senha } = req.body;
    try {
        const u = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (!u.rows.length) return res.status(400).json({ error: 'E-mail ou senha inválidos.' });
        if (!await bcrypt.compare(senha, u.rows[0].senha_hash))
            return res.status(400).json({ error: 'E-mail ou senha inválidos.' });
        if (!u.rows[0].ativo && !u.rows[0].is_admin)
            return res.status(403).json({ error: 'CONTA_INATIVA', msg: 'Conta aguarda aprovação do administrador.' });
        const token = jwt.sign({ id: u.rows[0].id, is_admin: u.rows[0].is_admin, ativo: u.rows[0].ativo }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user: { id: u.rows[0].id, nome: u.rows[0].nome, email: u.rows[0].email, is_admin: u.rows[0].is_admin, ativo: u.rows[0].ativo } });
    } catch { res.status(500).json({ error: 'Erro no login.' }); }
});

app.post('/api/auth/pin', async (req, res) => {
    const { email, pin } = req.body;
    try {
        const u = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (!u.rows.length) return res.status(400).json({ error: 'Motorista não encontrado.' });
        if (!await bcrypt.compare(pin.toString(), u.rows[0].pin_hash))
            return res.status(400).json({ error: 'PIN incorreto.' });
        if (!u.rows[0].ativo && !u.rows[0].is_admin)
            return res.status(403).json({ error: 'CONTA_INATIVA', msg: 'Conta aguarda aprovação do administrador.' });
        const token = jwt.sign({ id: u.rows[0].id, is_admin: u.rows[0].is_admin, ativo: u.rows[0].ativo }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user: { id: u.rows[0].id, nome: u.rows[0].nome, email: u.rows[0].email, is_admin: u.rows[0].is_admin } });
    } catch { res.status(500).json({ error: 'Erro no PIN.' }); }
});

app.get('/api/auth/me', verificarTokenJWT, async (req, res) => {
    try {
        const u = await pool.query('SELECT id, nome, email, telefone, is_admin, ativo FROM users WHERE id = $1', [req.user.id]);
        res.json(u.rows[0]);
    } catch { res.status(500).json({ error: 'Erro ao buscar perfil.' }); }
});

// =====================================================================================
// ADMIN
// =====================================================================================
app.get('/api/admin/usuarios', verificarTokenJWT, verificarAdmin, async (req, res) => {
    try {
        const u = await pool.query('SELECT id, nome, email, telefone, is_admin, ativo, criado_em FROM users ORDER BY criado_em DESC');
        res.json(u.rows);
    } catch { res.status(500).json({ error: 'Erro ao buscar usuários.' }); }
});

// Ativar usuário
app.patch('/api/admin/usuarios/:id/ativar', verificarTokenJWT, verificarAdmin, async (req, res) => {
    try {
        await pool.query('UPDATE users SET ativo = TRUE WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Erro ao ativar.' }); }
});

// Desativar usuário
app.patch('/api/admin/usuarios/:id/desativar', verificarTokenJWT, verificarAdmin, async (req, res) => {
    try {
        await pool.query('UPDATE users SET ativo = FALSE WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Erro ao desativar.' }); }
});

// Validar limite de via
app.patch('/api/limites-via/:id/validar', verificarTokenJWT, verificarAdmin, async (req, res) => {
    try {
        await pool.query('UPDATE limites_via SET validado = TRUE WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Erro ao validar.' }); }
});

// Admin remove qualquer limite
app.delete('/api/admin/limites-via/:id', verificarTokenJWT, verificarAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM limites_via WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Erro ao remover.' }); }
});

// =====================================================================================
// RADARES
// =====================================================================================
app.get('/api/radares', async (req, res) => {
    try {
        const r = await pool.query(`SELECT r.*, u.nome as nome_usuario FROM radares r LEFT JOIN users u ON r.user_id = u.id ORDER BY r.criado_em DESC`);
        res.json(r.rows);
    } catch { res.status(500).json({ error: 'Erro ao buscar radares.' }); }
});

app.post('/api/radares', verificarTokenJWT, verificarAtivo, async (req, res) => {
    const { local, lat, lon, velocidade } = req.body;
    try {
        if (!local || !lat || !lon || !velocidade) return res.status(400).json({ error: 'Dados incompletos.' });
        const r = await pool.query('INSERT INTO radares (user_id, local, lat, lon, velocidade) VALUES ($1,$2,$3,$4,$5) RETURNING *', [req.user.id, local, lat, lon, velocidade]);
        res.json(r.rows[0]);
    } catch { res.status(500).json({ error: 'Erro ao publicar radar.' }); }
});

app.delete('/api/radares/:id', verificarTokenJWT, async (req, res) => {
    try {
        const r = await pool.query('SELECT * FROM radares WHERE id = $1', [req.params.id]);
        if (!r.rows.length) return res.status(404).json({ error: 'Não encontrado.' });
        if (r.rows[0].user_id !== req.user.id && !req.user.is_admin) return res.status(403).json({ error: 'Permissão negada.' });
        await pool.query('DELETE FROM radares WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Erro ao remover.' }); }
});

// =====================================================================================
// LIMITES DE VIA
// =====================================================================================
app.get('/api/limites-via', async (req, res) => {
    try {
        const r = await pool.query(`SELECT l.*, u.nome as nome_usuario FROM limites_via l LEFT JOIN users u ON l.user_id = u.id ORDER BY l.criado_em DESC`);
        res.json(r.rows);
    } catch { res.status(500).json({ error: 'Erro ao buscar limites.' }); }
});

app.post('/api/limites-via', verificarTokenJWT, verificarAtivo, async (req, res) => {
    const { descricao, lat, lon, velocidade } = req.body;
    try {
        if (!descricao || !lat || !lon || !velocidade) return res.status(400).json({ error: 'Dados incompletos.' });
        const r = await pool.query('INSERT INTO limites_via (user_id, descricao, lat, lon, velocidade) VALUES ($1,$2,$3,$4,$5) RETURNING *', [req.user.id, descricao, lat, lon, velocidade]);
        res.json(r.rows[0]);
    } catch { res.status(500).json({ error: 'Erro ao salvar limite.' }); }
});

app.delete('/api/limites-via/:id', verificarTokenJWT, async (req, res) => {
    try {
        const r = await pool.query('SELECT * FROM limites_via WHERE id = $1', [req.params.id]);
        if (!r.rows.length) return res.status(404).json({ error: 'Não encontrado.' });
        if (r.rows[0].user_id !== req.user.id && !req.user.is_admin) return res.status(403).json({ error: 'Permissão negada.' });
        await pool.query('DELETE FROM limites_via WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Erro ao remover.' }); }
});

// =====================================================================================
// ALERTAS (Blitz, Obras, Interdição — expiram em 24h)
// =====================================================================================
app.get('/api/alertas', async (req, res) => {
    try {
        // Remove expirados automaticamente
        await pool.query('DELETE FROM alertas WHERE expira_em < NOW()');
        const r = await pool.query(`SELECT a.*, u.nome as nome_usuario FROM alertas a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.criado_em DESC`);
        res.json(r.rows);
    } catch { res.status(500).json({ error: 'Erro ao buscar alertas.' }); }
});

app.post('/api/alertas', verificarTokenJWT, verificarAtivo, async (req, res) => {
    const { tipo, descricao, lat, lon } = req.body;
    try {
        if (!tipo || !lat || !lon) return res.status(400).json({ error: 'Dados incompletos.' });
        const r = await pool.query(
            `INSERT INTO alertas (user_id, tipo, descricao, lat, lon, expira_em)
             VALUES ($1,$2,$3,$4,$5, NOW() + INTERVAL '24 hours') RETURNING *`,
            [req.user.id, tipo, descricao || tipo, lat, lon]
        );
        res.json(r.rows[0]);
    } catch { res.status(500).json({ error: 'Erro ao salvar alerta.' }); }
});

app.delete('/api/alertas/:id', verificarTokenJWT, async (req, res) => {
    try {
        const r = await pool.query('SELECT * FROM alertas WHERE id = $1', [req.params.id]);
        if (!r.rows.length) return res.status(404).json({ error: 'Não encontrado.' });
        if (r.rows[0].user_id !== req.user.id && !req.user.is_admin) return res.status(403).json({ error: 'Permissão negada.' });
        await pool.query('DELETE FROM alertas WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Erro ao remover.' }); }
});

// =====================================================================================
// FRONT-END + PWA manifest
// =====================================================================================
app.get('/manifest.json', (req, res) => {
    res.json({
        name: 'Anti-Multa Goiânia',
        short_name: 'Anti-Multa',
        description: 'Monitoramento de radares em tempo real',
        start_url: '/',
        display: 'standalone',
        background_color: '#1a1c25',
        theme_color: '#0079f2',
        orientation: 'portrait',
        icons: [
            { src: '/icon-192.png', sizes: '192x192', type: 'image/png' },
            { src: '/icon-512.png', sizes: '512x512', type: 'image/png' }
        ]
    });
});

app.get('/sw.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.send(`
const CACHE = 'anti-multa-v1';
const ASSETS = ['/', '/manifest.json'];
self.addEventListener('install', e => {
    e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
    self.skipWaiting();
});
self.addEventListener('activate', e => {
    e.waitUntil(caches.keys().then(keys =>
        Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ));
    self.clients.claim();
});
self.addEventListener('fetch', e => {
    if (e.request.url.includes('/api/')) return;
    e.respondWith(
        fetch(e.request).catch(() => caches.match(e.request))
    );
});
    `);
});

app.use(express.static(path.join(__dirname, 'public')));
app.get(/^\/(.*)$/, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`=== ANTI-MULTA GOIÂNIA SERVIDO NA PORTA ${PORT} ===`));
