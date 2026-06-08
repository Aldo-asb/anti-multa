// Servidor de Produção Full-Stack: v9.0
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'ASB_AUTOMACAO_INDUSTRIAL_GOIANIA_SECRET_KEY';

// ✅ POOLER DO SUPABASE COM O HOST DA AWS
const pool = new Pool({
    host:     'aws-1-sa-east-1.pooler.supabase.com',
    port:     5432,
    database: 'postgres',
    user:     'postgres.mcpzdtewuqmbxxlrttfc',
    password: 'JPgo514lZaUYpdDN',
    ssl: {
        rejectUnauthorized: false
    },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
});

// MOTOR DE INICIALIZAÇÃO E CRIAÇÃO AUTOMÁTICA DAS TABELAS RELACIONAIS
async function inicializarBancoDeDados() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                nome VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                senha_hash VARCHAR(255) NOT NULL,
                pin_hash VARCHAR(255) NOT NULL,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

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
        console.log("=== BANCO DE DADOS POSTGRESQL SINCRONIZADO COM SUCESSO ===");
    } catch (err) {
        console.error("ERRO CRÍTICO AO INICIALIZAR BANCO DE DADOS:", err);
    }
}
inicializarBancoDeDados();

// =====================================================================================
// ENDPOINTS DE AUTENTICAÇÃO
// =====================================================================================

app.post('/api/auth/register', async (req, res) => {
    const { nome, email, senha, pin } = req.body;
    try {
        if (!nome || !email || !senha || !pin) return res.status(400).json({ error: "Preencha todos os campos." });
        
        const senhaHash = await bcrypt.hash(senha, 10);
        const pinHash = await bcrypt.hash(pin.toString(), 10);

        const novoUsuario = await pool.query(
            'INSERT INTO users (nome, email, senha_hash, pin_hash) VALUES ($1, $2, $3, $4) RETURNING id, nome, email',
            [nome, email, senhaHash, pinHash]
        );

        const token = jwt.sign({ id: novoUsuario.rows[0].id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user: novoUsuario.rows[0] });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Este e-mail já está cadastrado." });
        res.status(500).json({ error: "Erro interno no servidor de cadastro." });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, senha } = req.body;
    try {
        const usuario = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (usuario.rows.length === 0) return res.status(400).json({ error: "E-mail ou senha inválidos." });

        const senhaValida = await bcrypt.compare(senha, usuario.rows[0].senha_hash);
        if (!senhaValida) return res.status(400).json({ error: "E-mail ou senha inválidos." });

        const token = jwt.sign({ id: usuario.rows[0].id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user: { id: usuario.rows[0].id, nome: usuario.rows[0].nome, email: usuario.rows[0].email } });
    } catch (err) {
        res.status(500).json({ error: "Erro interno no servidor de login." });
    }
});

app.post('/api/auth/pin', async (req, res) => {
    const { email, pin } = req.body;
    try {
        const usuario = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (usuario.rows.length === 0) return res.status(400).json({ error: "Motorista não encontrado." });

        const pinValido = await bcrypt.compare(pin.toString(), usuario.rows[0].pin_hash);
        if (!pinValido) return res.status(400).json({ error: "PIN de acesso incorreto." });

        const token = jwt.sign({ id: usuario.rows[0].id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user: { id: usuario.rows[0].id, nome: usuario.rows[0].nome, email: usuario.rows[0].email } });
    } catch (err) {
        res.status(500).json({ error: "Erro interno na verificação do PIN." });
    }
});

function verificarTokenJWT(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: "Acesso negado. Token não fornecido." });

    try {
        const verificado = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
        req.user = verificado;
        next();
    } catch (err) {
        res.status(400).json({ error: "Token inválido ou expirado." });
    }
}

app.get('/api/auth/me', verificarTokenJWT, async (req, res) => {
    try {
        const usuario = await pool.query('SELECT id, nome, email FROM users WHERE id = $1', [req.user.id]);
        res.json(usuario.rows[0]);
    } catch (err) {
        res.status(500).json({ error: "Erro ao buscar dados do perfil." });
    }
});

// =====================================================================================
// ENDPOINTS DOS RADARES
// =====================================================================================

app.get('/api/radares', async (req, res) => {
    try {
        const todosRadares = await pool.query('SELECT * FROM radares ORDER BY criado_em DESC');
        res.json(todosRadares.rows);
    } catch (err) {
        res.status(500).json({ error: "Erro ao sincronizar banco de radares." });
    }
});

app.post('/api/radares', verificarTokenJWT, async (req, res) => {
    const { local, lat, lon, velocidade } = req.body;
    try {
        if (!local || !lat || !lon || !velocidade) return res.status(400).json({ error: "Dados geográficos incompletos." });

        const novoRadar = await pool.query(
            'INSERT INTO radares (user_id, local, lat, lon, velocidade) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [req.user.id, local, lat, lon, velocidade]
        );
        res.json(novoRadar.rows[0]);
    } catch (err) {
        res.status(500).json({ error: "Erro ao publicar novo radar." });
    }
});

app.delete('/api/radares/:id', verificarTokenJWT, async (req, res) => {
    const { id } = req.params;
    try {
        const radar = await pool.query('SELECT * FROM radares WHERE id = $1', [id]);
        if (radar.rows.length === 0) return res.status(404).json({ error: "Radar não localizado." });

        if (radar.rows[0].user_id !== req.user.id) {
            return res.status(403).json({ error: "Permissão negada." });
        }

        await pool.query('DELETE FROM radares WHERE id = $1', [id]);
        res.json({ success: true, message: "Radar removido com sucesso." });
    } catch (err) {
        res.status(500).json({ error: "Erro ao processar exclusão." });
    }
});

// Arquivos estáticos do front-end
app.use(express.static(path.join(__dirname, 'public')));
app.get(/^\/(.*)$/, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`=== ANTI-MULTA SERVIDO NA PORTA ${PORT} ===`));
