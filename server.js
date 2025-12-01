const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());

const SECRET_KEY = process.env.SECRET_KEY;
const SECURITY_WEBHOOK = process.env.WEBHOOK_SECURITY || null;

const failedAttempts = new Map();
const blockedIPs = new Set();

setInterval(() => {
    failedAttempts.clear();
}, 10 * 60 * 1000);

const WEBHOOKS = {
    logs: process.env.WEBHOOK_LOGS,
    brainrot_250k: process.env.WEBHOOK_250K,
    brainrot_1m: process.env.WEBHOOK_1M,
    brainrot_5m: process.env.WEBHOOK_5M,
    brainrot_10m: process.env.WEBHOOK_10M,
    brainrot_50m: process.env.WEBHOOK_50M
};

// ========================================
// SIMPLE TOKEN AUTH (FONCTIONNE VRAIMENT)
// ========================================
function verifyToken(token) {
    if (!token) return false;
    
    // Simple comparaison de token
    const expectedToken = crypto
        .createHash('sha256')
        .update(SECRET_KEY)
        .digest('hex');
    
    console.log('🔐 Expected token:', expectedToken);
    console.log('📨 Received token:', token);
    
    return token === expectedToken;
}

// ========================================
// Vérifier le timestamp (anti-replay)
// ========================================
function isTimestampValid(timestamp) {
    if (!timestamp) return false;
    
    const now = Date.now();
    const requestTime = parseInt(timestamp);
    
    if (isNaN(requestTime)) return false;
    
    const diff = Math.abs(now - requestTime);
    
    return diff < 60000; // 60 secondes au lieu de 30
}

// ========================================
// Valider le payload des logs
// ========================================
function validateLogsPayload(data) {
    const required = ['userId', 'playerName', 'displayName', 'accountAge', 'jobId', 'placeId', 'playersCount', 'executor', 'position', 'timestamp'];
    
    for (const field of required) {
        if (!data[field]) {
            return { valid: false, error: `Missing field: ${field}` };
        }
    }
    
    if (!isTimestampValid(data.timestamp)) {
        return { valid: false, error: 'Invalid or expired timestamp' };
    }
    
    if (typeof data.userId !== 'string' || !/^\d+$/.test(data.userId)) {
        return { valid: false, error: 'Invalid userId format' };
    }
    
    if (typeof data.playerName !== 'string' || data.playerName.length === 0) {
        return { valid: false, error: 'Invalid playerName' };
    }
    
    if (typeof data.accountAge !== 'string' || !/^\d+$/.test(data.accountAge)) {
        return { valid: false, error: 'Invalid accountAge' };
    }
    
    if (typeof data.placeId !== 'string' || !/^\d+$/.test(data.placeId)) {
        return { valid: false, error: 'Invalid placeId' };
    }
    
    if (typeof data.playersCount !== 'string' || !/^\d+$/.test(data.playersCount)) {
        return { valid: false, error: 'Invalid playersCount' };
    }
    
    const content = JSON.stringify(data);
    if (/@everyone|@here|<@\d+>|<@&\d+>/.test(content)) {
        return { valid: false, error: 'Ping detected in payload' };
    }
    
    return { valid: true };
}

// ========================================
// Valider le payload brainrot
// ========================================
function validateBrainrotPayload(data) {
    const required = ['brainrotName', 'generation', 'placeId', 'jobId', 'timestamp'];
    
    for (const field of required) {
        if (!data[field]) {
            return { valid: false, error: `Missing field: ${field}` };
        }
    }
    
    if (!isTimestampValid(data.timestamp)) {
        return { valid: false, error: 'Invalid or expired timestamp' };
    }
    
    if (typeof data.brainrotName !== 'string' || data.brainrotName.length === 0) {
        return { valid: false, error: 'Invalid brainrotName' };
    }
    
    if (typeof data.generation !== 'string') {
        return { valid: false, error: 'Invalid generation format' };
    }
    
    if (typeof data.placeId !== 'string' || !/^\d+$/.test(data.placeId)) {
        return { valid: false, error: 'Invalid placeId' };
    }
    
    if (typeof data.jobId !== 'string' || data.jobId.length === 0) {
        return { valid: false, error: 'Invalid jobId' };
    }
    
    const content = JSON.stringify(data);
    if (/@everyone|@here|<@\d+>|<@&\d+>/.test(content)) {
        return { valid: false, error: 'Ping detected in payload' };
    }
    
    return { valid: true };
}

// Health check
app.get('/', (req, res) => {
    res.json({ 
        status: 'online', 
        service: 'Kryos Webhook Proxy',
        version: '3.0.0 - Simple Token Auth'
    });
});

// ========================================
// ENDPOINT: Logs d'exécution
// ========================================
app.post('/api/logs', async (req, res) => {
    try {
        const token = req.headers['x-auth-token'];
        
        // 1. Vérifier le token
        if (!verifyToken(token)) {
            console.log('❌ Invalid token for logs');
            return res.status(403).json({ error: 'Invalid authentication token' });
        }
        
        // 2. Valider le contenu du payload
        const validation = validateLogsPayload(req.body);
        if (!validation.valid) {
            console.log('❌ Invalid payload for logs:', validation.error);
            return res.status(400).json({ error: validation.error });
        }
        
        const { 
            userId, 
            playerName, 
            displayName, 
            accountAge, 
            jobId, 
            placeId, 
            playersCount, 
            executor, 
            position 
        } = req.body;

        const timestamp = new Date().toISOString();
        const headshotUrl = `https://www.roblox.com/headshot-thumbnail/image?userId=${userId}&width=150&height=150&format=png`;

        const embed = {
            title: "🚀 • Script exécuté",
            description: `**${playerName}** a exécuté le script.\n\n> _Merci d'utiliser Kryos Hub_`,
            color: 0x1ABC9C,
            timestamp: timestamp,
            author: {
                name: `${playerName} • ${displayName}`,
                url: `https://www.roblox.com/users/${userId}/profile`,
                icon_url: headshotUrl
            },
            thumbnail: { url: headshotUrl },
            fields: [
                { name: "🆔 • User", value: `\`\`\`Name: ${playerName} | ID: ${userId}\`\`\``, inline: false },
                { name: "🏷️ • DisplayName", value: displayName, inline: true },
                { name: "📅 • Âge du compte", value: `${accountAge} jours`, inline: true },
                { name: "🌐 • Place / Serveur", value: `PlaceId: \`${placeId}\`\nJobId: \`${jobId}\``, inline: false },
                { name: "👥 • Joueurs", value: playersCount, inline: true },
                { name: "📍 • Position", value: position, inline: true },
                { name: "⚙️ • Executor", value: executor, inline: true }
            ],
            footer: { text: "Kryos Hub • Logs", icon_url: headshotUrl }
        };

        await axios.post(WEBHOOKS.logs, { embeds: [embed] });
        console.log('✅ Logs sent successfully');
        res.status(200).json({ success: true });

    } catch (error) {
        console.error('❌ Error sending logs:', error.message);
        res.status(500).json({ error: 'Failed to send logs' });
    }
});

// ========================================
// ENDPOINT: Notifications brainrot
// ========================================
app.post('/api/brainrot', async (req, res) => {
    try {
        const token = req.headers['x-auth-token'];
        
        // 1. Vérifier le token
        if (!verifyToken(token)) {
            console.log('❌ Invalid token for brainrot');
            return res.status(403).json({ error: 'Invalid authentication token' });
        }
        
        // 2. Valider le contenu du payload
        const validation = validateBrainrotPayload(req.body);
        if (!validation.valid) {
            console.log('❌ Invalid payload for brainrot:', validation.error);
            return res.status(400).json({ error: validation.error });
        }
        
        const { 
            brainrotName, 
            generation, 
            placeId, 
            jobId 
        } = req.body;

        // 3. Vérifier que la génération est un nombre valide
        const genNumber = parseFloat(generation.replace(/[^\d.]/g, ''));
        if (isNaN(genNumber) || genNumber < 250000) {
            return res.status(400).json({ error: 'Generation too low or invalid' });
        }

        let webhookUrl, embedColor;
        if (genNumber > 50000000) {
            webhookUrl = WEBHOOKS.brainrot_50m;
            embedColor = 0xFF0000;
        } else if (genNumber > 10000000) {
            webhookUrl = WEBHOOKS.brainrot_10m;
            embedColor = 0xFF6600;
        } else if (genNumber > 5000000) {
            webhookUrl = WEBHOOKS.brainrot_5m;
            embedColor = 0xFFCC00;
        } else if (genNumber > 1000000) {
            webhookUrl = WEBHOOKS.brainrot_1m;
            embedColor = 0x00FF00;
        } else {
            webhookUrl = WEBHOOKS.brainrot_250k;
            embedColor = 0x3498DB;
        }

        const timestamp = new Date().toISOString();
        const joinLink = `https://chillihub1.github.io/chillihub-joiner/?placeId=${placeId}&gameInstanceId=${jobId}`;
        const joinScript = `game:GetService("TeleportService"):TeleportToPlaceInstance(${placeId}, "${jobId}", game:GetService("Players").LocalPlayer)`;

        const embed = {
            title: "💎 | KRYOS NOTIFIER",
            color: embedColor,
            timestamp: timestamp,
            fields: [
                { name: "🧠 • Brainrot Name", value: `\`\`\`${brainrotName}\`\`\``, inline: true },
                { name: "⚡ • Generation", value: `\`\`\`${generation}\`\`\``, inline: true },
                { name: "🌐 • Place ID", value: `\`${placeId}\``, inline: false },
                { name: "🔑 • Job ID", value: `\`${jobId}\``, inline: false },
                { name: "➕ • Quick Join", value: `[▶️ Click to join the game](${joinLink})`, inline: false },
                { name: "📋 • Join Script (LUA)", value: `\`\`\`lua\n${joinScript}\n\`\`\``, inline: false }
            ],
            footer: { text: "Kryos Notifier on TOP" }
        };

        await axios.post(webhookUrl, { embeds: [embed] });
        console.log('✅ Brainrot notification sent successfully');
        res.status(200).json({ success: true });

    } catch (error) {
        console.error('❌ Error sending brainrot:', error.message);
        res.status(500).json({ error: 'Failed to send notification' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Kryos Webhook Proxy (Simple Token) running on port ${PORT}`);
    console.log(`🔐 Auth Token: ${crypto.createHash('sha256').update(SECRET_KEY).digest('hex').substring(0, 16)}...`);
});
