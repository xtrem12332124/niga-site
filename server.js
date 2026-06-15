const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { Readable } = require('stream');

let sodium;
try { sodium = require('sodium-native'); } catch (e) { sodium = require('libsodium-wrappers'); }

const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, EmbedBuilder } = require('discord.js');
const { joinVoiceChannel, createAudioPlayer, createAudioResource, VoiceConnectionStatus, AudioPlayerStatus, StreamType } = require('@discordjs/voice');
require('dotenv').config();

const SECRET_KEY_XOR = 'hKkEySsEcReT2024XoR';
const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);

const checkHost = (req, res, next) => next();
const checkBannedIp = async (req, res, next) => {
    const clientIp = req.ip || req.connection.remoteAddress;
    try {
        const row = await dbGet("SELECT value FROM settings WHERE key = ?", ['banned_ip_' + clientIp]);
        if (row) {
            return res.status(403).send('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Acesso Bloqueado</title><style>body{background:#0b0b0e;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center}.card{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);padding:40px;border-radius:16px}h1{color:#ef4444;font-size:28px;margin-bottom:10px}p{color:#888}</style></head><body><div class="card"><h1>🚫 Acesso Bloqueado</h1><p>Seu IP foi bloqueado por atividade suspeita.</p></div></body></html>');
        }
    } catch (e) {}
    next();
};
const requireAdmin = (req, res, next) => (req.session && req.session.isAdmin) ? next() : res.status(403).json({ success: false, error: 'Acesso Negado' });
const requireClient = (req, res, next) => (req.session && (req.session.isClient || req.session.isAdmin)) ? next() : res.status(401).json({ success: false, error: 'Login Necessário' });
const requireOwner = (req, res, next) => (req.session && req.session.isAdmin && req.session.adminRole === 'owner') ? next() : res.status(403).json({ success: false, error: 'Apenas o dono pode fazer isso' });

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
const dbPath = path.join(dataDir, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

const dbGet = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (err, row) => err ? reject(err) : resolve(row)));
const dbAll = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)));
const dbRun = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, function(err) { err ? reject(err) : resolve(this); }));

async function initSystem() {
    return new Promise(async (resolve) => {
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT UNIQUE, discord_id TEXT, username TEXT DEFAULT 'User', avatar_url TEXT DEFAULT 'https://cdn.discordapp.com/embed/avatars/0.png', hwid TEXT, is_banned INTEGER DEFAULT 0, expiry_date TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_login DATETIME, ip_address TEXT)`);
            db.run(`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'admin', discord_id TEXT, avatar_url TEXT DEFAULT 'https://cdn.discordapp.com/embed/avatars/1.png')`);
            db.run(`ALTER TABLE admins ADD COLUMN discord_id TEXT`, () => {});
            db.run(`ALTER TABLE admins ADD COLUMN avatar_url TEXT`, () => {});
            db.run(`ALTER TABLE admins ADD COLUMN discord_username TEXT`, () => {});
            db.run(`CREATE TABLE IF NOT EXISTS downloads (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, url TEXT, version TEXT, description TEXT, icon TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
            db.run(`CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, details TEXT, ip_address TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
            db.run(`CREATE TABLE IF NOT EXISTS settings (key TEXT UNIQUE, value TEXT)`);
        });

        try {
            const adminUser = process.env.OWNER_USER || 'admin';
            const adminPass = process.env.OWNER_PASS || 'admin';
            const existingOwner = await dbGet("SELECT * FROM admins WHERE role = 'owner'");
            if (!existingOwner || existingOwner.username !== adminUser || existingOwner.password !== adminPass) {
                await dbRun("DELETE FROM admins WHERE role = 'owner'");
                await dbRun("INSERT INTO admins (username, password, role) VALUES (?, ?, 'owner')", [adminUser, adminPass]);
            }

            const settingsRow = await dbGet("SELECT COUNT(*) as count FROM settings WHERE key = 'global_msg'");
            if (settingsRow && settingsRow.count === 0) {
                await dbRun("INSERT INTO settings (key, value) VALUES ('global_msg', 'Bem-vindo a KALI MODS')");
                await dbRun("INSERT INTO settings (key, value) VALUES ('maintenance', 'false')");
                await dbRun("INSERT INTO settings (key, value) VALUES ('bot_token', ?)", [process.env.DISCORD_BOT_TOKEN || '']);
                await dbRun("INSERT INTO settings (key, value) VALUES ('client_id', ?)", [process.env.DISCORD_CLIENT_ID || '']);
                await dbRun("INSERT INTO settings (key, value) VALUES ('voice_id', ?)", ['']);
                await dbRun("INSERT INTO settings (key, value) VALUES ('owner_id', ?)", ['']);
            }
            resolve();
        } catch (e) {
            console.error("Erro no DB init:", e);
            resolve();
        }
    });
}

function xorEncrypt(text, key) {
    let result = '';
    for (let i = 0; i < text.length; i++) {
        const textChar = text.charCodeAt(i);
        const keyChar = key.charCodeAt(i % key.length);
        const encrypted = textChar ^ keyChar;
        result += ('0' + encrypted.toString(16)).slice(-2);
    }
    return result;
}

function xorDecrypt(hex, key) {
    let result = '';
    for (let i = 0; i < hex.length; i += 2) {
        const hexByte = hex.substr(i, 2);
        const encrypted = parseInt(hexByte, 16);
        const keyChar = key.charCodeAt((i / 2) % key.length);
        const decrypted = encrypted ^ keyChar;
        result += String.fromCharCode(decrypted);
    }
    return result;
}

function encrypt(text) {
    return xorEncrypt(text, SECRET_KEY_XOR);
}

function decrypt(hex) {
    return xorDecrypt(hex, SECRET_KEY_XOR);
}

function logAction(action, details, ip) {
    db.run("INSERT INTO logs (action, details, ip_address) VALUES (?,?,?)", [action, details, ip]);
}

function updateUserDiscordData(discordId, username, avatarUrl) {
    db.run("UPDATE users SET username = ?, avatar_url = ? WHERE discord_id = ?", [username, avatarUrl, discordId]);
}

class Silence extends Readable {
    _read() {
        this.push(Buffer.from([0xF8, 0xFF, 0xFE]));
    }
}

const client = new Client({
    intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildVoiceStates]
});

let voiceConnection = null;

async function getBotConfig() {
    const rows = await dbAll("SELECT * FROM settings");
    const config = {};
    rows.forEach(r => config[r.key] = r.value);
    if (!config.bot_token) config.bot_token = process.env.DISCORD_BOT_TOKEN;
    if (!config.client_id) config.client_id = process.env.DISCORD_CLIENT_ID;
    return config;
}

async function startBot() {
    const config = await getBotConfig();
    
    if (!config.bot_token) {
        console.log("⚠️ Token do bot não configurado");
        return;
    }

    if (client.isReady()) {
        await client.destroy();
    }

    try {
        await client.login(config.bot_token);
        console.log(`🤖 Bot conectado: ${client.user.tag}`);
        
        if (sodium.ready) {
            await sodium.ready;
        }
        
        await registerCommands(config.client_id, config.bot_token);
        
        setTimeout(() => {
            connectToVoiceChannel(config.voice_id);
        }, 3000);
    } catch (error) {
        console.error("❌ Erro ao conectar bot:", error.message);
    }
}

async function connectToVoiceChannel(channelId) {
    if (!channelId) return;

    try {
        const channel = await client.channels.fetch(channelId).catch(() => null);
        
        if (!channel || !channel.isVoiceBased()) {
            return;
        }

        if (voiceConnection) {
            try {
                voiceConnection.destroy();
            } catch {}
            voiceConnection = null;
        }

        voiceConnection = joinVoiceChannel({
            channelId: channel.id,
            guildId: channel.guild.id,
            adapterCreator: channel.guild.voiceAdapterCreator,
            selfDeaf: true
        });

        voiceConnection.on('error', () => {});
        voiceConnection.on(VoiceConnectionStatus.Ready, () => {
            playSilence();
        });
    } catch (error) {}
}

function playSilence() {
    if (!voiceConnection) return;

    try {
        const player = createAudioPlayer();
        const resource = createAudioResource(new Silence(), {
            inputType: StreamType.Opus
        });
        
        player.play(resource);
        voiceConnection.subscribe(player);
        
        player.on(AudioPlayerStatus.Idle, () => {
            playSilence();
        });
    } catch (error) {}
}

async function registerCommands(clientId, token) {
    if (!clientId || !token) return;

    const commands = [
        new SlashCommandBuilder()
            .setName('ativar')
            .setDescription('Ative sua Key')
            .addStringOption(option =>
                option.setName('key')
                    .setDescription('Sua licença')
                    .setRequired(true)
            ),
        new SlashCommandBuilder()
            .setName('mykey')
            .setDescription('Status da sua key'),
        new SlashCommandBuilder()
            .setName('criarkey')
            .setDescription('[Admin] Criar uma nova key de licença')
            .addIntegerOption(option =>
                option.setName('dias')
                    .setDescription('Duração da key')
                    .setRequired(true)
                    .addChoices(
                        { name: '1 Dia', value: 1 },
                        { name: '7 Dias', value: 7 },
                        { name: '30 Dias', value: 30 },
                        { name: '90 Dias', value: 90 },
                        { name: '120 Dias', value: 120 },
                        { name: '999 Dias', value: 999 },
                    )
            )
    ].map(command => command.toJSON());

    const rest = new REST({ version: '10' }).setToken(token);

    try {
        await rest.put(Routes.applicationCommands(String(clientId)), {
            body: commands
        });
        console.log("✅ Comandos registrados com sucesso.");
    } catch (error) {
        console.error("❌ Erro ao registrar comandos:", error.message);
    }
}

client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;

    try {
        await interaction.deferReply({ ephemeral: true });
    } catch {
        return;
    }

    try {
        updateUserDiscordData(
            interaction.user.id,
            interaction.user.username,
            interaction.user.displayAvatarURL()
        );

        if (interaction.commandName === 'ativar') {
            const rawKey = interaction.options.getString('key');
            const key = rawKey.trim().toUpperCase();

            const row = await dbGet("SELECT * FROM users WHERE license_key = ?", [key]);

            if (!row) {
                const embed = new EmbedBuilder()
                    .setColor(0x1E40AF)
                    .setTitle('<:4702discordcrossemoji:1449850940738900190> Key Inválida')
                    .setDescription(`Key não encontrada: \`${key}\``);
                
                return interaction.editReply({ embeds: [embed] });
            }

            if (row.is_banned) {
                return interaction.editReply('<:7300lock:1449850956060688537> Key banida permanentemente.');
            }

            if (row.discord_id && row.discord_id !== interaction.user.id) {
                return interaction.editReply('<:4702discordcrossemoji:1449850940738900190> Key já vinculada a outro usuário.');
            }

            await dbRun(
                "UPDATE users SET discord_id = ?, username = ?, avatar_url = ? WHERE license_key = ?",
                [interaction.user.id, interaction.user.username, interaction.user.displayAvatarURL(), key]
            );

            logAction('DISCORD_LINK', `Key ${key} ativada`, 'BOT');

            const embed = new EmbedBuilder()
                .setColor(0x1E40AF)
                .setTitle('Key ativada <a:2786verifyblack:1449850839136075796>')
                .setDescription(`Key: **${key}**\nValidade: **${row.expiry_date}**`)
                .setThumbnail(interaction.user.displayAvatarURL());

            return interaction.editReply({ embeds: [embed] });
        }

        if (interaction.commandName === 'mykey') {
            const row = await dbGet("SELECT * FROM users WHERE discord_id = ?", [interaction.user.id]);

            if (!row) {
                return interaction.editReply('<:4702discordcrossemoji:1449850940738900190> Você não possui uma licença ativa.');
            }

            const embed = new EmbedBuilder()
                .setColor(0x1E40AF)
                .setTitle(`👤 ${interaction.user.username}`)
                .addFields(
                    { name: 'Key', value: `||${row.license_key}||`, inline: true },
                    { name: 'Validade', value: row.expiry_date, inline: true },
                    { name: 'Status', value: row.is_banned ? '<:4702discordcrossemoji:1449850940738900190> Banido' : '<:5483discordticemoji:1449850946182971412> Ativo', inline: true }
                )
                .setThumbnail(row.avatar_url);

            return interaction.editReply({ embeds: [embed] });
        }

        if (interaction.commandName === 'criarkey') {
            const config = await getBotConfig();
            const ownerId = config.owner_id;
            if (!ownerId || interaction.user.id !== ownerId) {
                return interaction.editReply('❌ Apenas o dono do bot pode usar este comando.');
            }

            const days = interaction.options.getInteger('dias');
            const key = "HK-" + crypto.randomBytes(4).toString('hex').toUpperCase();
            const date = new Date();
            date.setDate(date.getDate() + days);
            const expiryDate = date.toISOString().split('T')[0];

            await dbRun(
                "INSERT INTO users (license_key, expiry_date) VALUES (?, ?)",
                [key, expiryDate]
            );

            const embed = new EmbedBuilder()
                .setColor(0x1E40AF)
                .setTitle('✅ Key Criada')
                .addFields(
                    { name: 'Key', value: `||${key}||`, inline: true },
                    { name: 'Duração', value: `${days} dias`, inline: true },
                    { name: 'Expira em', value: expiryDate, inline: true }
                );

            return interaction.editReply({ embeds: [embed] });
        }

    } catch (error) {
        console.error("💥 Erro no comando:", error);
        interaction.editReply('❌ Ocorreu um erro interno.').catch(() => {});
    }
});

app.use(checkBannedIp);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.text());
app.use(express.static(path.join(__dirname, 'public')));
app.use(checkHost);

app.use(session({
    secret: 'hk_keys_secure_session',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production', sameSite: 'lax' }
}));

const checkMaintenance = async (req, res, next) => {
    if (req.session && req.session.isAdmin && req.session.adminRole === 'owner') return next();
    if (req.path === '/api/maintenance-status' || req.path === '/api/emergency-unban') return next();
    if (req.path.startsWith('/auth/')) return next();
    try {
        const row = await dbGet("SELECT value FROM settings WHERE key = 'maintenance'");
        if (row && row.value === 'true') {
            if (req.accepts('html')) {
                return res.status(503).send(`<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Manutenção</title><style>body{background:#0b0b0e;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center;margin:0}.card{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);padding:50px;border-radius:20px;max-width:400px}.icon{font-size:48px;margin-bottom:16px;opacity:0.4}h1{font-size:22px;font-weight:700;margin-bottom:8px}p{color:#888;font-size:14px;line-height:1.6}</style></head><body><div class="card"><div class="icon">🔧</div><h1>Sistema em Manutenção</h1><p>Estamos realizando atualizações.<br>Volte em alguns minutos.</p></div></body></html>`);
            }
            return res.status(503).json({ success: false, error: 'Sistema em manutenção' });
        }
    } catch (e) {}
    next();
};
app.use(checkMaintenance);

app.get('/api/maintenance-status', async (req, res) => {
    const row = await dbGet("SELECT value FROM settings WHERE key = 'maintenance'");
    res.json({ maintenance: row && row.value === 'true' });
});

// Discord OAuth2
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'http://localhost:8080/auth/discord/callback';

app.post('/auth/discord/login', async (req, res) => {
    const key = req.body.key ? req.body.key.trim().toUpperCase() : "";

    const maintenance = await dbGet("SELECT value FROM settings WHERE key = 'maintenance'");
    if (maintenance && maintenance.value === 'true') {
        return res.json({ success: false, error: "Sistema em manutenção" });
    }

    const user = await dbGet("SELECT * FROM users WHERE license_key = ? AND is_banned = 0", [key]);
    if (!user) {
        return res.json({ success: false, error: 'Key inválida ou banida' });
    }

    req.session.tempKey = key;
    req.session.tempUserId = user.id;

    const authUrl = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify`;
    res.json({ success: true, redirect: authUrl });
});

app.get('/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.redirect('/?error=no_code');

    const tempAdmin = req.session.tempAdmin;
    const tempKey = req.session.tempKey;
    const tempUserId = req.session.tempUserId;

    if (!tempKey && !tempAdmin) return res.redirect('/?error=session_expired');

    try {
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: DISCORD_REDIRECT_URI
            })
        });

        const tokenData = await tokenResponse.json();
        if (!tokenData.access_token) return res.redirect('/?error=auth_failed');

        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const discordUser = await userResponse.json();

        if (tempAdmin) {
            await dbRun("UPDATE admins SET discord_id = ?, discord_username = ?, avatar_url = ? WHERE username = ? AND role = ?", [discordUser.id, discordUser.username, `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`, tempAdmin.username, tempAdmin.role]);
            req.session.isAdmin = true;
            req.session.adminRole = tempAdmin.role;
            req.session.adminName = tempAdmin.username;
            delete req.session.tempAdmin;
            logAction('ADMIN_DISCORD_LOGIN', `Admin ${tempAdmin.username} autenticou com Discord`, req.ip);
            return res.redirect('/admin');
        }

        const user = await dbGet("SELECT * FROM users WHERE id = ?", [tempUserId]);
        if (!user) return res.redirect('/?error=user_not_found');

        if (user.discord_id && user.discord_id !== discordUser.id) {
            return res.redirect('/?error=already_linked');
        }

        await dbRun(
            "UPDATE users SET discord_id = ?, username = ?, avatar_url = ?, last_login = CURRENT_TIMESTAMP, ip_address = ? WHERE id = ?",
            [discordUser.id, discordUser.username, `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`, req.ip, user.id]
        );

        req.session.isClient = true;
        req.session.userId = user.id;
        req.session.userKey = user.license_key;
        delete req.session.tempKey;
        delete req.session.tempUserId;
        logAction('DISCORD_LOGIN', `Login Discord: ${discordUser.username} (${user.license_key})`, req.ip);

        res.redirect('/client');
    } catch (e) {
        console.error("Erro OAuth2 Discord:", e);
        res.redirect('/?error=server_error');
    }
});

app.get('/', (req, res) => {
    if (req.session.isAdmin) {
        return res.sendFile(path.join(__dirname, 'private/admin.html'));
    }
    if (req.session.isClient) {
        return res.sendFile(path.join(__dirname, 'private/client.html'));
    }
    res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.get('/admin', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'private/admin.html'));
});

app.get('/client', requireClient, (req, res) => {
    res.sendFile(path.join(__dirname, 'private/client.html'));
});

app.get('/auth/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/api/client/me', requireClient, async (req, res) => {
    try {
        const user = await dbGet("SELECT * FROM users WHERE id = ?", [req.session.userId]);
        if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });
        res.json(user);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.get('/api/client/settings', requireClient, async (req, res) => {
    try {
        const msg = await dbGet("SELECT value FROM settings WHERE key = 'global_msg'");
        res.json({ global_msg: msg ? msg.value : '' });
    } catch (e) {
        res.json({});
    }
});

app.get('/api/client/users', requireClient, async (req, res) => {
    try {
        const users = await dbAll("SELECT id, username, avatar_url, discord_id, created_at FROM users ORDER BY id DESC LIMIT 50");
        const admins = await dbAll("SELECT username, role, discord_id, avatar_url, discord_username FROM admins");
        
        const all = [
            ...admins.map(a => ({ 
                id: -1,
                username: a.discord_username || a.username, 
                role: a.role || 'admin', 
                avatar_url: a.avatar_url || 'https://cdn.discordapp.com/embed/avatars/1.png',
                discord_id: a.discord_id || null,
                created_at: null
            })),
            ...users.map(u => ({ 
                id: u.id,
                username: u.username, 
                role: 'cliente', 
                avatar_url: u.avatar_url || 'https://cdn.discordapp.com/embed/avatars/0.png',
                discord_id: u.discord_id || null,
                created_at: u.created_at
            }))
        ];
        
        res.json(all);
    } catch (e) {
        console.error("Erro rota users:", e);
        res.json([]);
    }
});

app.post('/auth/admin/login', async (req, res) => {
    let { username, password, phone } = req.body;
    username = (username || '').toString().trim();
    password = (password || '').toString();
    phone = (phone || '').toString().trim();
    
    const clientIp = req.ip || req.connection.remoteAddress;

    const admin = await dbGet(
        "SELECT * FROM admins WHERE username = ? AND password = ?",
        [username, password]
    );

    if (!admin) {
        return res.json({ success: false, error: 'Credenciais inválidas' });
    }

    const allowedPhones = (process.env.ALLOWED_PHONES || '17996787397,17996498097,17997053419').split(',').map(p => p.trim()).filter(Boolean);

    if (admin.role === 'owner') {
        if (!phone) {
            return res.json({ phone_required: true });
        }
        if (!allowedPhones.includes(phone)) {
            await dbRun("INSERT OR REPLACE INTO settings (key, value) VALUES ('banned_ip_' || ?, '1')", [clientIp]);
            logAction('IP_BAN', `IP bloqueado por telefone inválido: ${clientIp}`, clientIp);
            return res.json({ success: false, error: 'Número inválido - IP bloqueado' });
        }
    }

    req.session.tempAdmin = { username: admin.username, role: admin.role };
    const authUrl = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify`;
    return res.json({ success: true, redirect: authUrl });
});

app.post('/auth/client/login', async (req, res) => {
    const key = req.body.key ? req.body.key.trim().toUpperCase() : "";
    
    const maintenance = await dbGet(
        "SELECT value FROM settings WHERE key = 'maintenance'"
    );
    
    if (maintenance && maintenance.value === 'true') {
        return res.json({ success: false, msg: "Sistema em manutenção" });
    }

    const user = await dbGet(
        "SELECT * FROM users WHERE license_key = ? AND is_banned = 0",
        [key]
    );

    if (user) {
        req.session.isClient = true;
        req.session.userId = user.id;
        req.session.userKey = user.license_key;

        await dbRun(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP, ip_address = ? WHERE id = ?",
            [req.ip, user.id]
        );
        logAction('WEB_LOGIN', `Login web: ${user.license_key}`, req.ip);

        return res.json({ success: true, redirect: '/client' });
    }
    
    res.json({ success: false, error: 'Key inválida ou banida' });
});

app.get('/verify.php', async (req, res) => {
    try {
        const key = req.query.key ? req.query.key.trim().toUpperCase() : '';

        if (!key) {
            return res.json({ success: false, msg: 'Key não fornecida' });
        }

        const user = await dbGet("SELECT * FROM users WHERE license_key = ?", [key]);

        if (!user) {
            return res.json({ success: false, msg: 'Key inválida' });
        }

        if (user.is_banned) {
            return res.json({ success: false, msg: 'Key banida' });
        }

        if (user.expiry_date !== 'lifetime' && user.expiry_date !== '2099-12-31') {
            const expiryDate = new Date(user.expiry_date);
            const now = new Date();
            if (!isNaN(expiryDate.getTime()) && expiryDate < now) {
                return res.json({ success: false, msg: 'Key expirada' });
            }
        }

        let days;
        if (user.expiry_date === 'lifetime' || user.expiry_date === '2099-12-31') {
            days = '2099-12-31';
        } else {
            const expiryDate = new Date(user.expiry_date);
            const now = new Date();
            const diff = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
            days = diff > 0 ? diff : 0;
        }

        res.json({ success: true, key: user.license_key, expiry: user.expiry_date, days, username: user.username, hwid: user.hwid || '', ip: user.ip_address || '' });
    } catch (error) {
        console.error('Erro no verify:', error);
        res.json({ success: false, msg: 'Erro interno' });
    }
});

app.post('/api/loader/auth', async (req, res) => {
    try {
        const encryptedHex = req.body;
        
        if (!encryptedHex || typeof encryptedHex !== 'string') {
            const errorResponse = encrypt(JSON.stringify({ success: false, msg: "Dados inválidos" }));
            return res.send(errorResponse);
        }

        if (encryptedHex.length % 2 !== 0) {
            const errorResponse = encrypt(JSON.stringify({ success: false, msg: "Formato hexadecimal inválido" }));
            return res.send(errorResponse);
        }

        const decryptedText = decrypt(encryptedHex);
        
        if (!decryptedText) {
            const errorResponse = encrypt(JSON.stringify({ success: false, msg: "Falha na descriptografia" }));
            return res.send(errorResponse);
        }

        let data;
        try {
            data = JSON.parse(decryptedText);
        } catch (parseError) {
            console.error("❌ Erro ao parsear JSON:", parseError);
            const errorResponse = encrypt(JSON.stringify({ success: false, msg: "Dados corrompidos" }));
            return res.send(errorResponse);
        }

        const key = data.key ? data.key.trim().toUpperCase() : "";
        const hwid = data.hwid || "";

        if (!key) {
            const response = encrypt(JSON.stringify({ success: false, msg: "Key não fornecida" }));
            return res.send(response);
        }

        const user = await dbGet("SELECT * FROM users WHERE license_key = ?", [key]);

        if (!user) {
            const response = encrypt(JSON.stringify({ success: false, msg: "Key inválida" }));
            return res.send(response);
        }

        if (user.is_banned) {
            const response = encrypt(JSON.stringify({ success: false, msg: "Conta banida" }));
            return res.send(response);
        }

        if (user.expiry_date !== 'lifetime' && user.expiry_date !== '2099-12-31') {
            const expiryDate = new Date(user.expiry_date);
            const now = new Date();
            
            if (isNaN(expiryDate.getTime())) {
                const response = encrypt(JSON.stringify({ success: false, msg: "Data de expiração inválida" }));
                return res.send(response);
            }
            
            if (expiryDate < now) {
                const response = encrypt(JSON.stringify({ success: false, msg: "Key expirada" }));
                return res.send(response);
            }
        }

        if (!user.hwid) {
            await dbRun(
                "UPDATE users SET hwid = ?, last_login = CURRENT_TIMESTAMP, ip_address = ? WHERE id = ?",
                [hwid, req.ip, user.id]
            );
        } else if (user.hwid !== hwid) {
            logAction('HWID_FAIL', `Key ${key} - HWID mismatch`, req.ip);
            const response = encrypt(JSON.stringify({ success: false, msg: "HWID inválido" }));
            return res.send(response);
        } else {
            await dbRun(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP, ip_address = ? WHERE id = ?",
                [req.ip, user.id]
            );
        }

        logAction('LOADER_LOGIN', `Login C++: ${user.username}`, req.ip);

        const globalMsg = await dbGet(
            "SELECT value FROM settings WHERE key = 'global_msg'"
        );

        const responseData = {
            success: true,
            username: user.username,
            avatar: user.avatar_url,
            expiry: user.expiry_date,
            msg: globalMsg ? globalMsg.value : ""
        };

        const encryptedResponse = encrypt(JSON.stringify(responseData));
        res.send(encryptedResponse);

    } catch (error) {
        console.error("💥 Erro crítico auth loader:", error);
        const errorResponse = encrypt(JSON.stringify({ 
            success: false, 
            msg: "Erro interno do servidor" 
        }));
        res.send(errorResponse);
    }
});

app.get('/api/emergency-unban', async (req, res) => {
    const { token } = req.query;
    if (!token || token !== 'hk_keys_secure_session') return res.status(401).send('Token invalido');
    await dbRun("DELETE FROM settings WHERE key LIKE 'banned_ip_%'");
    res.send('Todos os IPs foram desbanidos. Tente logar novamente.');
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
    res.json({
        username: req.session.adminName,
        role: req.session.adminRole
    });
});

app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
    const totalUsers = await dbGet("SELECT COUNT(*) as count FROM users");
    const maintenance = await dbGet("SELECT value FROM settings WHERE key = 'maintenance'");
    const logs = await dbAll("SELECT * FROM logs WHERE action = 'LOADER_LOGIN' ORDER BY id DESC LIMIT 10");
    const chartData = await dbAll(`
        SELECT date(created_at) as date, COUNT(*) as count 
        FROM logs 
        WHERE action = 'LOADER_LOGIN' AND created_at > date('now', '-7 days') 
        GROUP BY date(created_at)
    `);

    res.json({
        total: totalUsers.count,
        maintenance: maintenance ? maintenance.value : 'false',
        loaderLogs: logs,
        chartData: chartData || []
    });
});

app.get('/api/users', requireAdmin, async (req, res) => {
    const users = await dbAll("SELECT * FROM users ORDER BY id DESC");
    res.json(users);
});

app.post('/api/users/add-days', requireAdmin, async (req, res) => {
    const { id, days } = req.body;

    const user = await dbGet("SELECT expiry_date FROM users WHERE id = ?", [id]);
    
    if (!user) {
        return res.json({ success: false, error: 'Usuário não encontrado' });
    }

    let newDate;
    if (user.expiry_date === 'lifetime' || user.expiry_date === '2099-12-31') {
        newDate = '2099-12-31';
    } else {
        const currentDate = new Date(user.expiry_date);
        const now = new Date();
        
        if (isNaN(currentDate.getTime()) || currentDate < now) {
            currentDate.setTime(now.getTime());
        }
        
        currentDate.setDate(currentDate.getDate() + parseInt(days));
        newDate = currentDate.toISOString().split('T')[0];
    }

    await dbRun("UPDATE users SET expiry_date = ? WHERE id = ?", [newDate, id]);
    
    res.json({ success: true, newDate });
});

app.post('/api/users/create', requireAdmin, async (req, res) => {
    const { days } = req.body;
    
    const key = "HK-" + crypto.randomBytes(4).toString('hex').toUpperCase();
    
    let expiryDate;
    if (days === 'lifetime') {
        expiryDate = '2099-12-31';
    } else {
        const date = new Date();
        date.setDate(date.getDate() + parseInt(days));
        expiryDate = date.toISOString().split('T')[0];
    }

    await dbRun(
        "INSERT INTO users (license_key, expiry_date) VALUES (?, ?)",
        [key, expiryDate]
    );

    console.log(`✨ Key criada: ${key}`);
    
    res.json({ success: true, key, expiryDate });
});

app.post('/api/users/action', requireAdmin, async (req, res) => {
    const { id, action } = req.body;
    
    const queries = {
        ban: "UPDATE users SET is_banned = 1 WHERE id = ?",
        unban: "UPDATE users SET is_banned = 0 WHERE id = ?",
        reset: "UPDATE users SET hwid = NULL WHERE id = ?",
        delete: "DELETE FROM users WHERE id = ?"
    };

    const query = queries[action];
    
    if (query) {
        await dbRun(query, [id]);
        res.json({ success: true });
    } else {
        res.json({ success: false, error: 'Ação inválida' });
    }
});

app.get('/api/admin/settings', requireOwner, async (req, res) => {
    const rows = await dbAll("SELECT * FROM settings");
    const settings = {};
    
    rows.forEach(row => {
        settings[row.key] = row.value;
    });
    
    res.json(settings);
});

app.post('/api/admin/settings', requireOwner, async (req, res) => {
    const updates = req.body;
    
    for (const [key, value] of Object.entries(updates)) {
        if (value !== undefined) {
            await dbRun(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                [key, value]
            );
        }
    }
    
    res.json({ success: true });
});

app.post('/api/admin/restart-bot', requireOwner, async (req, res) => {
    startBot();
    res.json({ success: true, msg: 'Bot reiniciado' });
});

app.get('/api/downloads', requireClient, async (req, res) => {
    const downloads = await dbAll("SELECT * FROM downloads ORDER BY id DESC");
    res.json(downloads);
});

app.post('/api/downloads/add', requireOwner, async (req, res) => {
    const { name, url, version } = req.body;
    
    await dbRun(
        "INSERT INTO downloads (name, url, version, description, icon) VALUES (?, ?, ?, ?, ?)",
        [name, url, version, '', 'fas fa-file']
    );
    
    res.json({ success: true });
});

app.post('/api/downloads/del', requireOwner, async (req, res) => {
    const { id } = req.body;
    
    await dbRun("DELETE FROM downloads WHERE id = ?", [id]);
    
    res.json({ success: true });
});

app.get('/api/admin/logs', requireAdmin, async (req, res) => {
    const logs = await dbAll("SELECT * FROM logs ORDER BY id DESC LIMIT 100");
    res.json(logs);
});

app.post('/api/admin/clear-logs', requireOwner, async (req, res) => {
    await dbRun("DELETE FROM logs");
    res.json({ success: true });
});

app.post('/api/admin/create-admin', requireOwner, async (req, res) => {
    const { username, password, role } = req.body;
    
    await dbRun(
        "INSERT INTO admins (username, password, role) VALUES (?, ?, ?)",
        [username, password, role || 'admin']
    );
    
    res.json({ success: true });
});

app.post('/api/admin/delete-admin', requireOwner, async (req, res) => {
    const { id } = req.body;
    
    await dbRun("DELETE FROM admins WHERE id = ?", [id]);
    
    res.json({ success: true });
});

app.get('/api/admin/admins', requireOwner, async (req, res) => {
    const admins = await dbAll("SELECT * FROM admins");
    res.json(admins);
});

app.post('/api/admin/send-message', requireOwner, async (req, res) => {
    const { message } = req.body;
    
    await dbRun(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('global_msg', ?)",
        [message]
    );
    
    res.json({ success: true });
});

app.post('/api/admin/toggle-maintenance', requireOwner, async (req, res) => {
    const { enabled } = req.body;
    
    await dbRun(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('maintenance', ?)",
        [enabled ? 'true' : 'false']
    );
    
    res.json({ success: true });
});

app.post('/api/admin/ban-ip', requireOwner, async (req, res) => {
    const { ip } = req.body;
    
    await dbRun("INSERT OR REPLACE INTO settings (key, value) VALUES ('banned_ip_' || ?, '1')", [ip]);
    logAction('IP_BAN', `IP banido manualmente: ${ip}`, req.ip);
    
    res.json({ success: true });
});

app.post('/api/admin/unban-ip', requireOwner, async (req, res) => {
    const { ip } = req.body;
    
    await dbRun("DELETE FROM settings WHERE key = ?", ['banned_ip_' + ip]);
    logAction('IP_UNBAN', `IP desbanido: ${ip}`, req.ip);
    
    res.json({ success: true });
});

app.get('/api/admin/banned-ips', requireOwner, async (req, res) => {
    const rows = await dbAll("SELECT key FROM settings WHERE key LIKE 'banned_ip_%'");
    const ips = rows.map(r => r.key.replace('banned_ip_', ''));
    res.json(ips);
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    const totalUsers = await dbGet("SELECT COUNT(*) as count FROM users");
    const activeUsers = await dbGet("SELECT COUNT(*) as count FROM users WHERE is_banned = 0");
    const bannedUsers = await dbGet("SELECT COUNT(*) as count FROM users WHERE is_banned = 1");
    const todayLogins = await dbGet("SELECT COUNT(*) as count FROM logs WHERE action = 'LOADER_LOGIN' AND date(created_at) = date('now')");
    const totalLogins = await dbGet("SELECT COUNT(*) as count FROM logs WHERE action = 'LOADER_LOGIN'");
    
    res.json({
        totalUsers: totalUsers.count,
        activeUsers: activeUsers.count,
        bannedUsers: bannedUsers.count,
        todayLogins: todayLogins.count,
        totalLogins: totalLogins.count
    });
});

(async () => {
    console.log("🔄 Inicializando sistema...");
    await initSystem();
    await startBot();
    
    setInterval(() => {
        getBotConfig().then(config => {
            if (!voiceConnection && config.voice_id) {
                connectToVoiceChannel(config.voice_id);
            }
        });
    }, 600000);

    app.listen(PORT, '0.0.0.0', () => {
        console.log(`🚀 Servidor online na porta ${PORT}`);
        console.log(`🔐 Sistema KALI MODS operacional`);
    });
})();