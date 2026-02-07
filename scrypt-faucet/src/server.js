/**
 * SCRYPT Faucet
 *
 * Dispenses free testnet SCRYPT coins for development/testing
 */

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

// Configuration
const CONFIG = {
    port: process.env.PORT || 3004,
    rpcUrl: process.env.RPC_URL || 'http://127.0.0.1:9332',
    rpcUser: process.env.RPC_USER || 'scryptrpc',
    rpcPass: process.env.RPC_PASS || 'scryptrpcpassword',

    // Faucet settings
    payoutAmount: 10,           // SCRYPT per claim
    cooldownHours: 24,          // Hours between claims per IP/address
    maxDailyPayout: 10000,      // Max total daily payout
    minConfirmations: 1,        // Min confirmations before new claim

    // Wallet (faucet's wallet)
    faucetAddress: process.env.FAUCET_ADDRESS || ''
};

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Rate limiting - 5 requests per minute per IP
const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: 'Too many requests, please try again later' }
});
app.use('/api/', limiter);

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

// In-memory claim tracking (use Redis in production)
const claims = new Map();  // address -> { lastClaim, totalClaimed }
const ipClaims = new Map(); // ip -> lastClaim

let dailyPayout = 0;
let lastDayReset = Date.now();

// Reset daily limit
function checkDailyReset() {
    const now = Date.now();
    if (now - lastDayReset > 24 * 60 * 60 * 1000) {
        dailyPayout = 0;
        lastDayReset = now;
    }
}

// Validate SCRYPT address
function isValidAddress(address) {
    // SCRYPT mainnet addresses start with 'S', testnet with 's'
    if (!address || address.length < 26 || address.length > 35) {
        return false;
    }
    if (!/^[Ss][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address)) {
        return false;
    }
    return true;
}

// Get client IP
function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] ||
           req.headers['x-real-ip'] ||
           req.connection.remoteAddress ||
           req.ip;
}

// ==================== API ENDPOINTS ====================

// Get faucet info
app.get('/api/info', async (req, res) => {
    try {
        checkDailyReset();

        let balance = 0;
        try {
            balance = await rpcCall('getbalance');
        } catch (e) {
            // Node not running
        }

        res.json({
            payoutAmount: CONFIG.payoutAmount,
            cooldownHours: CONFIG.cooldownHours,
            balance: balance,
            dailyRemaining: CONFIG.maxDailyPayout - dailyPayout,
            address: CONFIG.faucetAddress || 'Not configured'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Check if address can claim
app.get('/api/check/:address', (req, res) => {
    const address = req.params.address;

    if (!isValidAddress(address)) {
        return res.json({ canClaim: false, reason: 'Invalid address format' });
    }

    const claim = claims.get(address);
    const now = Date.now();
    const cooldownMs = CONFIG.cooldownHours * 60 * 60 * 1000;

    if (claim && (now - claim.lastClaim) < cooldownMs) {
        const remainingMs = cooldownMs - (now - claim.lastClaim);
        const remainingHours = Math.ceil(remainingMs / (60 * 60 * 1000));
        return res.json({
            canClaim: false,
            reason: `Please wait ${remainingHours} hours before claiming again`,
            nextClaim: new Date(claim.lastClaim + cooldownMs).toISOString()
        });
    }

    res.json({ canClaim: true, amount: CONFIG.payoutAmount });
});

// Claim SCRYPT
app.post('/api/claim', async (req, res) => {
    try {
        const { address } = req.body;
        const clientIP = getClientIP(req);

        // Validate address
        if (!isValidAddress(address)) {
            return res.status(400).json({ error: 'Invalid SCRYPT address' });
        }

        // Check daily limit
        checkDailyReset();
        if (dailyPayout >= CONFIG.maxDailyPayout) {
            return res.status(429).json({ error: 'Daily faucet limit reached. Try again tomorrow!' });
        }

        const now = Date.now();
        const cooldownMs = CONFIG.cooldownHours * 60 * 60 * 1000;

        // Check address cooldown
        const addressClaim = claims.get(address);
        if (addressClaim && (now - addressClaim.lastClaim) < cooldownMs) {
            const remainingHours = Math.ceil((cooldownMs - (now - addressClaim.lastClaim)) / (60 * 60 * 1000));
            return res.status(429).json({
                error: `Address already claimed. Wait ${remainingHours} hours.`
            });
        }

        // Check IP cooldown
        const ipClaim = ipClaims.get(clientIP);
        if (ipClaim && (now - ipClaim) < cooldownMs) {
            const remainingHours = Math.ceil((cooldownMs - (now - ipClaim)) / (60 * 60 * 1000));
            return res.status(429).json({
                error: `IP already claimed. Wait ${remainingHours} hours.`
            });
        }

        // Send SCRYPT via RPC
        let txid;
        try {
            txid = await rpcCall('sendtoaddress', [address, CONFIG.payoutAmount]);
        } catch (e) {
            console.error(`Faucet RPC error: ${e.message}`);
            return res.status(503).json({
                error: 'Faucet is temporarily unavailable. Please try again later.',
                details: 'Node connection failed'
            });
        }

        // Record claim
        claims.set(address, {
            lastClaim: now,
            totalClaimed: (addressClaim?.totalClaimed || 0) + CONFIG.payoutAmount
        });
        ipClaims.set(clientIP, now);
        dailyPayout += CONFIG.payoutAmount;

        res.json({
            success: true,
            amount: CONFIG.payoutAmount,
            txid,
            message: `Sent ${CONFIG.payoutAmount} SCRYPT to ${address}`,
            nextClaim: new Date(now + cooldownMs).toISOString()
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get recent claims (for display)
app.get('/api/recent', (req, res) => {
    const recent = [];
    const now = Date.now();

    claims.forEach((claim, address) => {
        if (now - claim.lastClaim < 24 * 60 * 60 * 1000) {
            recent.push({
                address: address.slice(0, 8) + '...' + address.slice(-4),
                amount: CONFIG.payoutAmount,
                time: claim.lastClaim
            });
        }
    });

    res.json(recent.sort((a, b) => b.time - a.time).slice(0, 10));
});

// ==================== START SERVER ====================

app.listen(CONFIG.port, () => {
    console.log(`
+===============================================+
|            SCRYPT FAUCET                      |
+===============================================+
|  Server: http://localhost:${CONFIG.port}              |
|  Payout: ${CONFIG.payoutAmount} SCRYPT per claim              |
|  Cooldown: ${CONFIG.cooldownHours} hours                       |
+===============================================+
    `);
});
