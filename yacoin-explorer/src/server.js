/**
 * Scrypt Coin Block Explorer - Backend Server
 */

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// Configuration
const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:9332';
const RPC_USER = process.env.RPC_USER || 'rpcuser';
const RPC_PASS = process.env.RPC_PASS || 'rpcpass';
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// RPC Helper
async function rpcCall(method, params = []) {
    try {
        const response = await axios.post(RPC_URL, {
            jsonrpc: '1.0',
            id: Date.now(),
            method,
            params
        }, {
            auth: { username: RPC_USER, password: RPC_PASS },
            headers: { 'Content-Type': 'application/json' }
        });
        return response.data.result;
    } catch (error) {
        console.error(`RPC Error (${method}):`, error.message);
        throw error;
    }
}

// Cache for performance
let cachedInfo = null;
let lastInfoUpdate = 0;

async function getCachedInfo() {
    const now = Date.now();
    if (!cachedInfo || now - lastInfoUpdate > 5000) {
        cachedInfo = await rpcCall('getblockchaininfo');
        lastInfoUpdate = now;
    }
    return cachedInfo;
}

// API Routes

// Get blockchain info
app.get('/api/info', async (req, res) => {
    try {
        const info = await getCachedInfo();
        const miningInfo = await rpcCall('getmininginfo');
        const networkInfo = await rpcCall('getnetworkinfo');

        res.json({
            blocks: info.blocks,
            difficulty: miningInfo.difficulty,
            hashrate: miningInfo.networkhashps,
            connections: networkInfo.connections,
            version: networkInfo.subversion,
            chain: info.chain
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get latest blocks
app.get('/api/blocks', async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 10, 50);
        const info = await getCachedInfo();
        const blocks = [];

        for (let i = 0; i < limit && info.blocks - i >= 0; i++) {
            const hash = await rpcCall('getblockhash', [info.blocks - i]);
            const block = await rpcCall('getblock', [hash]);
            blocks.push({
                height: block.height,
                hash: block.hash,
                time: block.time,
                txCount: block.tx.length,
                size: block.size,
                difficulty: block.difficulty
            });
        }

        res.json(blocks);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get block by height or hash
app.get('/api/block/:id', async (req, res) => {
    try {
        let hash = req.params.id;

        // If numeric, get hash from height
        if (/^\d+$/.test(hash)) {
            hash = await rpcCall('getblockhash', [parseInt(hash)]);
        }

        const block = await rpcCall('getblock', [hash, 2]); // Verbose with tx details

        res.json({
            height: block.height,
            hash: block.hash,
            previousHash: block.previousblockhash,
            nextHash: block.nextblockhash,
            merkleRoot: block.merkleroot,
            time: block.time,
            difficulty: block.difficulty,
            nonce: block.nonce,
            size: block.size,
            txCount: block.tx.length,
            transactions: block.tx.map(tx => ({
                txid: tx.txid,
                size: tx.size,
                vout: tx.vout.map(v => ({
                    value: v.value,
                    address: v.scriptPubKey?.addresses?.[0] || 'Unknown'
                }))
            }))
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get transaction
app.get('/api/tx/:txid', async (req, res) => {
    try {
        const tx = await rpcCall('getrawtransaction', [req.params.txid, true]);

        res.json({
            txid: tx.txid,
            hash: tx.hash,
            size: tx.size,
            blockHash: tx.blockhash,
            blockHeight: tx.blockheight,
            confirmations: tx.confirmations,
            time: tx.time,
            inputs: tx.vin.map(vin => ({
                txid: vin.txid,
                vout: vin.vout,
                coinbase: vin.coinbase
            })),
            outputs: tx.vout.map(vout => ({
                value: vout.value,
                n: vout.n,
                address: vout.scriptPubKey?.addresses?.[0] || 'Unknown',
                type: vout.scriptPubKey?.type
            }))
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get address info
app.get('/api/address/:address', async (req, res) => {
    try {
        const address = req.params.address;

        // Get balance
        const balance = await rpcCall('getaddressbalance', [{ addresses: [address] }]);

        // Get UTXOs
        const utxos = await rpcCall('getaddressutxos', [{ addresses: [address] }]);

        // Get transaction history
        const txids = await rpcCall('getaddresstxids', [{ addresses: [address] }]);

        // Get token balances
        let tokens = [];
        try {
            tokens = await rpcCall('listaddressesbytoken', [address]);
        } catch (e) {
            // Token RPC might not be available
        }

        res.json({
            address,
            balance: balance.balance / 1e8,
            received: balance.received / 1e8,
            sent: (balance.received - balance.balance) / 1e8,
            txCount: txids.length,
            utxoCount: utxos.length,
            tokens,
            recentTxs: txids.slice(-10).reverse()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all tokens
app.get('/api/tokens', async (req, res) => {
    try {
        const tokens = await rpcCall('listtokens', ['*', true]);

        const tokenList = Object.entries(tokens).map(([name, data]) => ({
            name,
            amount: data.amount,
            units: data.units,
            reissuable: data.reissuable,
            hasIPFS: data.has_ipfs,
            ipfsHash: data.ipfs_hash
        }));

        res.json(tokenList);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get token info
app.get('/api/token/:name', async (req, res) => {
    try {
        const data = await rpcCall('gettokendata', [req.params.name]);
        const addresses = await rpcCall('listaddressesbytoken', [req.params.name]);

        res.json({
            name: data.name,
            amount: data.amount,
            units: data.units,
            reissuable: data.reissuable,
            hasIPFS: data.has_ipfs,
            ipfsHash: data.ipfs_hash,
            holderCount: Object.keys(addresses).length,
            holders: Object.entries(addresses).slice(0, 100).map(([addr, bal]) => ({
                address: addr,
                balance: bal
            }))
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Search (block, tx, address, token)
app.get('/api/search/:query', async (req, res) => {
    const query = req.params.query.trim();

    try {
        // Check if it's a block height
        if (/^\d+$/.test(query)) {
            const hash = await rpcCall('getblockhash', [parseInt(query)]);
            return res.json({ type: 'block', id: query });
        }

        // Check if it's a transaction hash (64 hex chars)
        if (/^[a-fA-F0-9]{64}$/.test(query)) {
            try {
                await rpcCall('getrawtransaction', [query, true]);
                return res.json({ type: 'tx', id: query });
            } catch (e) {
                // Might be a block hash
                try {
                    await rpcCall('getblock', [query]);
                    return res.json({ type: 'block', id: query });
                } catch (e2) {
                    // Not found
                }
            }
        }

        // Check if it's an address (starts with S or s)
        if (/^[Ss][a-zA-Z0-9]{25,34}$/.test(query)) {
            return res.json({ type: 'address', id: query });
        }

        // Check if it's a token
        try {
            await rpcCall('gettokendata', [query.toUpperCase()]);
            return res.json({ type: 'token', id: query.toUpperCase() });
        } catch (e) {
            // Not a token
        }

        res.json({ type: 'notfound', id: query });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Mempool
app.get('/api/mempool', async (req, res) => {
    try {
        const mempool = await rpcCall('getrawmempool', [true]);
        const info = await rpcCall('getmempoolinfo');

        res.json({
            size: info.size,
            bytes: info.bytes,
            transactions: Object.entries(mempool).slice(0, 50).map(([txid, data]) => ({
                txid,
                size: data.size,
                fee: data.fee,
                time: data.time
            }))
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Rich list
app.get('/api/richlist', async (req, res) => {
    try {
        // This would need address indexing enabled
        // For now, return placeholder
        res.json({
            message: 'Rich list requires full address index',
            topHolders: []
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// WebSocket for live updates
io.on('connection', (socket) => {
    console.log('Client connected');

    // Send new blocks
    const blockInterval = setInterval(async () => {
        try {
            const info = await getCachedInfo();
            socket.emit('newBlock', { height: info.blocks });
        } catch (e) {}
    }, 10000);

    socket.on('disconnect', () => {
        clearInterval(blockInterval);
        console.log('Client disconnected');
    });
});

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Start server
server.listen(PORT, () => {
    console.log(`Scrypt Explorer running on http://localhost:${PORT}`);
});
