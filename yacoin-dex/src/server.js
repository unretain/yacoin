/**
 * Scrypt DEX - Simple Decentralized Exchange
 *
 * AMM-style token trading for Scrypt blockchain
 * Similar to Uniswap V2 model
 */

const express = require('express');
const axios = require('axios');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const http = require('http');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*' }
});

// Configuration
const CONFIG = {
    port: process.env.PORT || 3003,
    rpcUrl: process.env.RPC_URL || 'http://127.0.0.1:9332',
    rpcUser: process.env.RPC_USER || 'scryptrpc',
    rpcPass: process.env.RPC_PASS || 'scryptrpcpassword',
    baseCurrency: 'SCRYPT',  // Native token ticker
    tradeFee: 0.003, // 0.3% trading fee
    lpFee: 0.0025,   // 0.25% goes to LPs
    protocolFee: 0.0005 // 0.05% protocol fee
};

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

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

// ==================== AMM STATE ====================

// Liquidity pools: token -> { reserveToken, reserveSCRYPT, totalLP, lpHolders }
const pools = new Map();

// LP token balances: poolId -> { address -> balance }
const lpBalances = new Map();

// Trade history
const trades = [];

// Pending transactions
const pendingTxs = new Map();

// ==================== AMM MATH ====================

// Calculate output amount using constant product formula (x * y = k)
function getAmountOut(amountIn, reserveIn, reserveOut) {
    const amountInWithFee = amountIn * (1 - CONFIG.tradeFee);
    const numerator = amountInWithFee * reserveOut;
    const denominator = reserveIn + amountInWithFee;
    return numerator / denominator;
}

// Calculate input amount needed for desired output
function getAmountIn(amountOut, reserveIn, reserveOut) {
    const numerator = reserveIn * amountOut;
    const denominator = (reserveOut - amountOut) * (1 - CONFIG.tradeFee);
    return numerator / denominator + 1;
}

// Calculate price impact
function getPriceImpact(amountIn, reserveIn, reserveOut) {
    const idealOut = amountIn * (reserveOut / reserveIn);
    const actualOut = getAmountOut(amountIn, reserveIn, reserveOut);
    return ((idealOut - actualOut) / idealOut) * 100;
}

// Calculate LP tokens to mint
function calculateLPTokens(amountToken, amountSCRY, pool) {
    if (!pool || pool.totalLP === 0) {
        // First liquidity provision
        return Math.sqrt(amountToken * amountSCRY);
    }
    // Proportional to existing pool
    const tokenRatio = amountToken / pool.reserveToken;
    const scryRatio = amountSCRY / pool.reserveSCRYPT;
    const ratio = Math.min(tokenRatio, scryRatio);
    return ratio * pool.totalLP;
}

// ==================== API ENDPOINTS ====================

// Get all pools
app.get('/api/pools', (req, res) => {
    const poolList = [];
    pools.forEach((pool, token) => {
        poolList.push({
            token,
            ...pool,
            price: pool.reserveSCRYPT / pool.reserveToken,
            tvl: pool.reserveSCRYPT * 2 // TVL in SCRY equivalent
        });
    });
    res.json(poolList.sort((a, b) => b.tvl - a.tvl));
});

// Get pool by token
app.get('/api/pool/:token', (req, res) => {
    const token = req.params.token.toUpperCase();
    const pool = pools.get(token);

    if (!pool) {
        return res.status(404).json({ error: 'Pool not found' });
    }

    res.json({
        token,
        ...pool,
        price: pool.reserveSCRYPT / pool.reserveToken,
        tvl: pool.reserveSCRYPT * 2
    });
});

// Get swap quote
app.post('/api/quote', (req, res) => {
    const { tokenIn, tokenOut, amountIn } = req.body;

    // SCRY -> Token swap
    if (tokenIn === 'SCRYPT') {
        const pool = pools.get(tokenOut.toUpperCase());
        if (!pool) {
            return res.status(404).json({ error: 'Pool not found' });
        }

        const amountOut = getAmountOut(amountIn, pool.reserveSCRYPT, pool.reserveToken);
        const priceImpact = getPriceImpact(amountIn, pool.reserveSCRYPT, pool.reserveToken);

        return res.json({
            tokenIn: 'SCRYPT',
            tokenOut: tokenOut.toUpperCase(),
            amountIn,
            amountOut,
            price: pool.reserveSCRYPT / pool.reserveToken,
            priceImpact,
            fee: amountIn * CONFIG.tradeFee,
            minimumReceived: amountOut * 0.995 // 0.5% slippage
        });
    }

    // Token -> SCRY swap
    if (tokenOut === 'SCRYPT') {
        const pool = pools.get(tokenIn.toUpperCase());
        if (!pool) {
            return res.status(404).json({ error: 'Pool not found' });
        }

        const amountOut = getAmountOut(amountIn, pool.reserveToken, pool.reserveSCRYPT);
        const priceImpact = getPriceImpact(amountIn, pool.reserveToken, pool.reserveSCRYPT);

        return res.json({
            tokenIn: tokenIn.toUpperCase(),
            tokenOut: 'SCRYPT',
            amountIn,
            amountOut,
            price: pool.reserveSCRYPT / pool.reserveToken,
            priceImpact,
            fee: amountOut * CONFIG.tradeFee,
            minimumReceived: amountOut * 0.995
        });
    }

    // Token -> Token swap (via SCRY)
    const poolIn = pools.get(tokenIn.toUpperCase());
    const poolOut = pools.get(tokenOut.toUpperCase());

    if (!poolIn || !poolOut) {
        return res.status(404).json({ error: 'Pool not found' });
    }

    const scryAmount = getAmountOut(amountIn, poolIn.reserveToken, poolIn.reserveSCRYPT);
    const amountOut = getAmountOut(scryAmount, poolOut.reserveSCRYPT, poolOut.reserveToken);

    res.json({
        tokenIn: tokenIn.toUpperCase(),
        tokenOut: tokenOut.toUpperCase(),
        amountIn,
        amountOut,
        route: [tokenIn.toUpperCase(), 'SCRYPT', tokenOut.toUpperCase()],
        priceImpact: getPriceImpact(amountIn, poolIn.reserveToken, poolIn.reserveSCRYPT) +
                     getPriceImpact(scryAmount, poolOut.reserveSCRYPT, poolOut.reserveToken),
        fee: amountIn * CONFIG.tradeFee * 2,
        minimumReceived: amountOut * 0.99
    });
});

// Execute swap
app.post('/api/swap', async (req, res) => {
    try {
        const { tokenIn, tokenOut, amountIn, minAmountOut, userAddress } = req.body;

        // Validate
        if (!tokenIn || !tokenOut || !amountIn || !userAddress) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        let pool, amountOut, updatedReserveIn, updatedReserveOut;

        if (tokenIn === 'SCRYPT') {
            pool = pools.get(tokenOut.toUpperCase());
            if (!pool) return res.status(404).json({ error: 'Pool not found' });

            amountOut = getAmountOut(amountIn, pool.reserveSCRYPT, pool.reserveToken);

            if (amountOut < minAmountOut) {
                return res.status(400).json({ error: 'Slippage too high' });
            }

            pool.reserveSCRYPT += amountIn;
            pool.reserveToken -= amountOut;

        } else if (tokenOut === 'SCRYPT') {
            pool = pools.get(tokenIn.toUpperCase());
            if (!pool) return res.status(404).json({ error: 'Pool not found' });

            amountOut = getAmountOut(amountIn, pool.reserveToken, pool.reserveSCRYPT);

            if (amountOut < minAmountOut) {
                return res.status(400).json({ error: 'Slippage too high' });
            }

            pool.reserveToken += amountIn;
            pool.reserveSCRYPT -= amountOut;
        }

        // Record trade
        const trade = {
            id: uuidv4(),
            tokenIn: tokenIn.toUpperCase(),
            tokenOut: tokenOut.toUpperCase(),
            amountIn,
            amountOut,
            user: userAddress,
            timestamp: Date.now(),
            txid: `swap_${uuidv4().slice(0, 16)}`
        };

        trades.unshift(trade);
        if (trades.length > 100) trades.pop();

        const tradeVolume = tokenIn === 'SCRYPT' ? amountIn : amountOut;
        pool.volume24h = (pool.volume24h || 0) + tradeVolume;

        // Record price history
        const tokenName = tokenIn === 'SCRYPT' ? tokenOut.toUpperCase() : tokenIn.toUpperCase();
        const currentPrice = pool.reserveSCRYPT / pool.reserveToken;
        recordPrice(tokenName, currentPrice, tradeVolume);

        // Broadcast update
        io.emit('trade', trade);
        io.emit('pool_update', { token: tokenName, pool });

        res.json({
            success: true,
            trade,
            message: `Swapped ${amountIn} ${tokenIn} for ${amountOut.toFixed(8)} ${tokenOut}`
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add liquidity
app.post('/api/liquidity/add', async (req, res) => {
    try {
        const { token, amountToken, amountSCRY, userAddress } = req.body;

        const tokenUpper = token.toUpperCase();
        let pool = pools.get(tokenUpper);

        if (!pool) {
            // Create new pool
            pool = {
                reserveToken: 0,
                reserveSCRYPT: 0,
                totalLP: 0,
                lpHolders: new Map(),
                volume24h: 0,
                createdAt: Date.now()
            };
            pools.set(tokenUpper, pool);
            lpBalances.set(tokenUpper, new Map());
        }

        // Calculate LP tokens
        const lpTokens = calculateLPTokens(amountToken, amountSCRY, pool);

        // Update pool
        pool.reserveToken += amountToken;
        pool.reserveSCRYPT += amountSCRY;
        pool.totalLP += lpTokens;

        // Update user LP balance
        const userLPBalances = lpBalances.get(tokenUpper);
        const currentBalance = userLPBalances.get(userAddress) || 0;
        userLPBalances.set(userAddress, currentBalance + lpTokens);

        io.emit('pool_update', { token: tokenUpper, pool });

        res.json({
            success: true,
            lpTokens,
            pool: {
                token: tokenUpper,
                reserveToken: pool.reserveToken,
                reserveSCRYPT: pool.reserveSCRYPT,
                totalLP: pool.totalLP,
                yourLP: userLPBalances.get(userAddress),
                yourShare: (userLPBalances.get(userAddress) / pool.totalLP) * 100
            }
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Remove liquidity
app.post('/api/liquidity/remove', async (req, res) => {
    try {
        const { token, lpAmount, userAddress } = req.body;

        const tokenUpper = token.toUpperCase();
        const pool = pools.get(tokenUpper);

        if (!pool) {
            return res.status(404).json({ error: 'Pool not found' });
        }

        const userLPBalances = lpBalances.get(tokenUpper);
        const userBalance = userLPBalances.get(userAddress) || 0;

        if (lpAmount > userBalance) {
            return res.status(400).json({ error: 'Insufficient LP balance' });
        }

        // Calculate tokens to return
        const share = lpAmount / pool.totalLP;
        const tokenAmount = pool.reserveToken * share;
        const scryAmount = pool.reserveSCRYPT * share;

        // Update pool
        pool.reserveToken -= tokenAmount;
        pool.reserveSCRYPT -= scryAmount;
        pool.totalLP -= lpAmount;

        // Update user balance
        userLPBalances.set(userAddress, userBalance - lpAmount);

        io.emit('pool_update', { token: tokenUpper, pool });

        res.json({
            success: true,
            tokenAmount,
            scryAmount,
            remainingLP: userLPBalances.get(userAddress)
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get user LP positions
app.get('/api/liquidity/:address', (req, res) => {
    const address = req.params.address;
    const positions = [];

    lpBalances.forEach((balances, token) => {
        const balance = balances.get(address);
        if (balance && balance > 0) {
            const pool = pools.get(token);
            const share = balance / pool.totalLP;
            positions.push({
                token,
                lpBalance: balance,
                sharePercent: share * 100,
                tokenValue: pool.reserveToken * share,
                scryValue: pool.reserveSCRYPT * share,
                totalValue: pool.reserveSCRYPT * share * 2
            });
        }
    });

    res.json(positions);
});

// Get recent trades
app.get('/api/trades', (req, res) => {
    const limit = parseInt(req.query.limit) || 20;
    res.json(trades.slice(0, limit));
});

// Get trades for a specific token
app.get('/api/trades/:token', (req, res) => {
    const token = req.params.token.toUpperCase();
    const limit = parseInt(req.query.limit) || 20;

    const tokenTrades = trades.filter(t =>
        t.tokenIn === token || t.tokenOut === token
    ).slice(0, limit);

    res.json(tokenTrades);
});

// Price history storage (per token)
const priceHistory = new Map();

// Get price history (real data from trades)
app.get('/api/price/:token', (req, res) => {
    const token = req.params.token.toUpperCase();
    const pool = pools.get(token);

    if (!pool) {
        return res.status(404).json({ error: 'Pool not found' });
    }

    const currentPrice = pool.reserveSCRYPT / pool.reserveToken;
    const history = priceHistory.get(token) || [];

    // Calculate 24h price change from actual history
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
    const oldestPrice = history.find(h => h.timestamp >= oneDayAgo)?.price || currentPrice;
    const priceChange24h = oldestPrice > 0 ? ((currentPrice - oldestPrice) / oldestPrice) * 100 : 0;

    res.json({
        token,
        currentPrice,
        priceChange24h,
        history: history.slice(-24) // Last 24 data points
    });
});

// Record price after each trade
function recordPrice(token, price, volume) {
    if (!priceHistory.has(token)) {
        priceHistory.set(token, []);
    }
    const history = priceHistory.get(token);
    history.push({
        timestamp: Date.now(),
        price,
        volume
    });
    // Keep only last 7 days of data
    const oneWeekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    while (history.length > 0 && history[0].timestamp < oneWeekAgo) {
        history.shift();
    }
}

// ==================== WEBSOCKET ====================

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // Send initial pool data
    const poolList = [];
    pools.forEach((pool, token) => {
        poolList.push({ token, ...pool });
    });
    socket.emit('pools', poolList);

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// ==================== START SERVER ====================

server.listen(CONFIG.port, () => {
    console.log(`
+===============================================+
|              SCRYPT DEX                       |
+===============================================+
|  Server running on http://localhost:${CONFIG.port}    |
|  Trade tokens on Scrypt blockchain!           |
|                                               |
|  Trading Fee: ${(CONFIG.tradeFee * 100).toFixed(1)}%                         |
|  LP Fee: ${(CONFIG.lpFee * 100).toFixed(2)}%                           |
|                                               |
|  Pools: ${pools.size} (create by adding liquidity)    |
+===============================================+
    `);
});
