/**
 * Scrypt Token Launchpad
 *
 * Easy memecoin/token creation platform
 * Similar to Solana's pump.fun
 */

const express = require('express');
const axios = require('axios');
const multer = require('multer');
const sharp = require('sharp');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const http = require('http');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*' }
});

// Configuration
const CONFIG = {
    port: process.env.PORT || 3002,
    rpcUrl: process.env.RPC_URL || 'http://127.0.0.1:9332',
    rpcUser: process.env.RPC_USER || 'scryptrpc',
    rpcPass: process.env.RPC_PASS || 'scryptrpcpassword',
    uploadDir: path.join(__dirname, '../uploads'),
    maxImageSize: 5 * 1024 * 1024, // 5MB
    creationFee: 100, // SCRYPT tokens required to create a token
    explorerUrl: 'http://localhost:3001'
};

// Ensure upload directory exists
if (!fs.existsSync(CONFIG.uploadDir)) {
    fs.mkdirSync(CONFIG.uploadDir, { recursive: true });
}

// Multer config for image uploads
const storage = multer.diskStorage({
    destination: CONFIG.uploadDir,
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `${uuidv4()}${ext}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: CONFIG.maxImageSize },
    fileFilter: (req, file, cb) => {
        const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (allowed.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, GIF, and WebP allowed.'));
        }
    }
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(CONFIG.uploadDir));

// RPC helper
async function rpcCall(method, params = []) {
    try {
        const response = await axios.post(CONFIG.rpcUrl, {
            jsonrpc: '1.0',
            id: Date.now(),
            method,
            params
        }, {
            auth: {
                username: CONFIG.rpcUser,
                password: CONFIG.rpcPass
            }
        });
        return response.data.result;
    } catch (error) {
        console.error(`RPC Error (${method}):`, error.message);
        throw error;
    }
}

// In-memory token database (would use real DB in production)
const tokens = new Map();
const pendingTokens = new Map();

// Token creation queue for live updates
const creationQueue = [];

// ==================== API ENDPOINTS ====================

// Get launchpad stats
app.get('/api/stats', async (req, res) => {
    try {
        const info = await rpcCall('getblockchaininfo').catch(() => null);

        res.json({
            tokensCreated: tokens.size,
            pendingCreations: pendingTokens.size,
            creationFee: CONFIG.creationFee,
            blockchain: info ? {
                blocks: info.blocks,
                chain: info.chain
            } : null
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get recent token launches
app.get('/api/tokens/recent', (req, res) => {
    const limit = parseInt(req.query.limit) || 20;
    const recentTokens = Array.from(tokens.values())
        .sort((a, b) => b.createdAt - a.createdAt)
        .slice(0, limit);

    res.json(recentTokens);
});

// Get trending tokens (by holder count or transaction volume)
app.get('/api/tokens/trending', (req, res) => {
    const limit = parseInt(req.query.limit) || 10;
    const trending = Array.from(tokens.values())
        .sort((a, b) => (b.holders || 0) - (a.holders || 0))
        .slice(0, limit);

    res.json(trending);
});

// Search tokens
app.get('/api/tokens/search', (req, res) => {
    const query = (req.query.q || '').toLowerCase();
    if (!query) {
        return res.json([]);
    }

    const results = Array.from(tokens.values())
        .filter(t =>
            t.name.toLowerCase().includes(query) ||
            t.ticker.toLowerCase().includes(query) ||
            (t.description || '').toLowerCase().includes(query)
        )
        .slice(0, 20);

    res.json(results);
});

// Get token details
app.get('/api/token/:ticker', async (req, res) => {
    const ticker = req.params.ticker.toUpperCase();
    const token = tokens.get(ticker);

    if (!token) {
        return res.status(404).json({ error: 'Token not found' });
    }

    // Try to get on-chain data
    try {
        const onChainData = await rpcCall('gettoken', [ticker]).catch(() => null);
        if (onChainData) {
            token.onChain = onChainData;
        }
    } catch (e) {}

    res.json(token);
});

// Upload token image
app.post('/api/upload', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No image uploaded' });
        }

        // Resize and optimize image
        const optimizedPath = path.join(
            CONFIG.uploadDir,
            `opt_${req.file.filename}`
        );

        await sharp(req.file.path)
            .resize(512, 512, { fit: 'cover' })
            .png({ quality: 80 })
            .toFile(optimizedPath);

        // Delete original
        fs.unlinkSync(req.file.path);

        const imageUrl = `/uploads/opt_${req.file.filename}`;
        res.json({ imageUrl });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Validate token creation request
app.post('/api/token/validate', (req, res) => {
    const { ticker, name, supply, decimals } = req.body;
    const errors = [];

    // Ticker validation
    if (!ticker || ticker.length < 3 || ticker.length > 8) {
        errors.push('Ticker must be 3-8 characters');
    }
    if (!/^[A-Z0-9]+$/.test(ticker)) {
        errors.push('Ticker must be uppercase letters and numbers only');
    }
    if (tokens.has(ticker) || pendingTokens.has(ticker)) {
        errors.push('Ticker already exists');
    }

    // Name validation
    if (!name || name.length < 2 || name.length > 32) {
        errors.push('Name must be 2-32 characters');
    }

    // Supply validation
    const supplyNum = parseInt(supply);
    if (isNaN(supplyNum) || supplyNum < 1 || supplyNum > 1000000000000) {
        errors.push('Supply must be between 1 and 1 trillion');
    }

    // Decimals validation
    const decimalsNum = parseInt(decimals);
    if (isNaN(decimalsNum) || decimalsNum < 0 || decimalsNum > 18) {
        errors.push('Decimals must be 0-18');
    }

    if (errors.length > 0) {
        return res.status(400).json({ valid: false, errors });
    }

    res.json({ valid: true, estimatedFee: CONFIG.creationFee });
});

// Create a new token
app.post('/api/token/create', async (req, res) => {
    try {
        const {
            ticker,
            name,
            supply,
            decimals,
            description,
            imageUrl,
            website,
            twitter,
            telegram,
            discord,
            creatorAddress
        } = req.body;

        // Validate
        const tickerUpper = ticker.toUpperCase();

        if (tokens.has(tickerUpper) || pendingTokens.has(tickerUpper)) {
            return res.status(400).json({ error: 'Ticker already exists' });
        }

        // Create pending token entry
        const tokenData = {
            id: uuidv4(),
            ticker: tickerUpper,
            name,
            supply: parseInt(supply),
            decimals: parseInt(decimals) || 8,
            description: description || '',
            imageUrl: imageUrl || '/images/default-token.png',
            website: website || '',
            twitter: twitter || '',
            telegram: telegram || '',
            discord: discord || '',
            creator: creatorAddress,
            createdAt: Date.now(),
            status: 'pending',
            holders: 1,
            txCount: 0
        };

        pendingTokens.set(tickerUpper, tokenData);

        // Execute the token creation RPC call
        try {
            // Call the issue RPC to create the token on-chain
            const txid = await rpcCall('issue', [
                tickerUpper,                    // token name
                parseInt(supply),               // amount
                '',                             // to_address (empty = wallet default)
                '',                             // change_address
                parseInt(decimals) || 8,        // units/decimals
                true,                           // reissuable
                false                           // has_ipfs
            ]);

            tokenData.status = 'active';
            tokenData.txid = txid;
            tokens.set(tickerUpper, tokenData);
            pendingTokens.delete(tickerUpper);

            // Broadcast to connected clients
            io.emit('token_created', tokenData);
            console.log(`Token created: ${tickerUpper} (${name}) - txid: ${txid}`);

        } catch (rpcError) {
            tokenData.status = 'failed';
            tokenData.error = rpcError.message;
            pendingTokens.delete(tickerUpper);
            io.emit('token_failed', tokenData);
            console.error(`Token creation failed: ${tickerUpper} - ${rpcError.message}`);

            return res.status(500).json({
                success: false,
                error: `Token creation failed: ${rpcError.message}`
            });
        }

        res.json({
            success: true,
            token: tokenData,
            message: 'Token created on blockchain',
            txid: tokenData.txid
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get token creation status
app.get('/api/token/status/:id', (req, res) => {
    const id = req.params.id;

    // Check active tokens
    for (const token of tokens.values()) {
        if (token.id === id) {
            return res.json(token);
        }
    }

    // Check pending tokens
    for (const token of pendingTokens.values()) {
        if (token.id === id) {
            return res.json(token);
        }
    }

    res.status(404).json({ error: 'Token not found' });
});

// Get token holders (mock data for demo)
app.get('/api/token/:ticker/holders', (req, res) => {
    const ticker = req.params.ticker.toUpperCase();
    const token = tokens.get(ticker);

    if (!token) {
        return res.status(404).json({ error: 'Token not found' });
    }

    // In real implementation, query blockchain for holder list
    const holders = [
        { address: token.creator, balance: token.supply, percentage: 100 }
    ];

    res.json({ ticker, holders, totalHolders: 1 });
});

// Airdrop tool (for token creators)
app.post('/api/token/:ticker/airdrop', async (req, res) => {
    const ticker = req.params.ticker.toUpperCase();
    const { recipients, amountEach, creatorAddress } = req.body;

    const token = tokens.get(ticker);
    if (!token) {
        return res.status(404).json({ error: 'Token not found' });
    }

    if (token.creator !== creatorAddress) {
        return res.status(403).json({ error: 'Only token creator can airdrop' });
    }

    // In real implementation, create and broadcast transactions
    res.json({
        success: true,
        message: `Airdrop of ${amountEach} ${ticker} to ${recipients.length} addresses initiated`,
        estimatedFee: recipients.length * 0.01
    });
});

// ==================== WEBSOCKET EVENTS ====================

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // Send recent tokens on connect
    socket.emit('recent_tokens', Array.from(tokens.values()).slice(-10));

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// ==================== START SERVER ====================

server.listen(CONFIG.port, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║              SCRYPT TOKEN LAUNCHPAD                       ║
╠═══════════════════════════════════════════════════════════╣
║  Server running on http://localhost:${CONFIG.port}                ║
║  Create memecoins and tokens easily!                      ║
║                                                           ║
║  RPC: ${CONFIG.rpcUrl}                          ║
║  Explorer: ${CONFIG.explorerUrl}                      ║
╚═══════════════════════════════════════════════════════════╝
    `);

    // Load existing tokens from blockchain on startup
    loadExistingTokens();
});

// Load tokens from blockchain
async function loadExistingTokens() {
    try {
        const tokenList = await rpcCall('listtokens', ['*', true]);
        if (tokenList && typeof tokenList === 'object') {
            Object.entries(tokenList).forEach(([name, data]) => {
                tokens.set(name, {
                    id: name,
                    ticker: name,
                    name: name,
                    supply: data.amount || 0,
                    decimals: data.units || 8,
                    description: '',
                    imageUrl: '/images/default-token.png',
                    creator: 'unknown',
                    createdAt: Date.now(),
                    status: 'active',
                    holders: 0,
                    txCount: 0,
                    onChain: data
                });
            });
            console.log(`Loaded ${tokens.size} tokens from blockchain`);
        }
    } catch (e) {
        console.log('Could not load tokens from blockchain (node may be offline):', e.message);
    }
}
