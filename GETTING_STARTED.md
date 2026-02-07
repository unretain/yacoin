# Getting Scrypt Coin Network Running

## Prerequisites

### Windows
- Visual Studio 2022 with C++ Desktop Development
- CUDA Toolkit 12.x (optional, for GPU mining)
- vcpkg for dependencies

### Linux/WSL (Recommended for building)
```bash
sudo apt-get update
sudo apt-get install build-essential libtool autotools-dev automake pkg-config \
    bsdmainutils python3 libssl-dev libevent-dev libboost-all-dev \
    libminiupnpc-dev libzmq3-dev libdb++-dev
```

## Quick Start with Regtest (Fastest Way to Test)

Regtest mode uses a tiny 16MB DAG and lets you mine blocks instantly.

### 1. Build the Node

**On Linux/WSL:**
```bash
cd scrypt-coin
./autogen.sh
./configure
make -j$(nproc)
```

**On Windows (with Visual Studio):**
Open the solution file in `build/` and build the Release configuration.

### 2. Create Config File

Create `~/.scrypt/scrypt.conf` (Linux) or `%APPDATA%\Scrypt\scrypt.conf` (Windows):

```ini
# Regtest mode for testing
regtest=1

# RPC settings
server=1
rpcuser=scryptrpc
rpcpassword=scryptrpcpassword
rpcport=29332
rpcallowip=127.0.0.1

# Mining
gen=1
genproclimit=1

# Logging
debug=1
printtoconsole=1
```

### 3. Start the Node

```bash
./src/scryptd -regtest -daemon
```

### 4. Mine Some Blocks

```bash
# Generate 101 blocks (100 needed for coinbase maturity + 1)
./src/scrypt-cli -regtest generate 101

# Check balance
./src/scrypt-cli -regtest getbalance
```

### 5. Create a Token

```bash
# Issue a new token
./src/scrypt-cli -regtest issue "MYTOKEN" 1000000

# Check token balance
./src/scrypt-cli -regtest listtokenbalancesbyaddress
```

## Mainnet Launch

For mainnet, the genesis block must first be mined. This is a one-time process:

### 1. Mine Genesis Block

The genesis block mining is done by running the node with special flags:
```bash
./src/scryptd -printtoconsole -debug
```

Watch for the genesis hash to be computed, then update `chainparams.cpp` with:
- `hashGenesisBlock`
- `nGenesisNonce`
- `hashGenesisMerkleRoot`

### 2. Rebuild and Distribute

After genesis is mined, rebuild the node and distribute to seed nodes.

## Running Web Apps

Start the web apps after the node is running:

```bash
# Terminal 1: Explorer (port 3001)
cd scrypt-explorer && npm install && npm start

# Terminal 2: Launchpad (port 3002)
cd scrypt-launchpad && npm install && npm start

# Terminal 3: DEX (port 3003)
cd scrypt-dex && npm install && npm start

# Terminal 4: Faucet (port 3004)
cd scrypt-faucet && npm install && npm start
```

## Network Specifications

| Parameter | Mainnet | Testnet | Regtest |
|-----------|---------|---------|---------|
| Port | 9333 | 19333 | 29333 |
| RPC Port | 9332 | 19332 | 29332 |
| Address Prefix | S | s | s |
| Initial DAG | 1 GB | 256 MB | 16 MB |
| Block Time | 60 sec | 60 sec | instant |

## RPC Commands

```bash
# Blockchain info
scrypt-cli getblockchaininfo

# Mining info
scrypt-cli getmininginfo

# Start mining
scrypt-cli setgenerate true 4  # 4 threads

# Token commands
scrypt-cli issue "TOKEN" 1000000        # Create token
scrypt-cli transfer "TOKEN" 100 "Saddr" # Send tokens
scrypt-cli listtokens                   # List all tokens
```

## Troubleshooting

### "Cannot find genesis block"
The genesis block hasn't been mined yet. Use regtest mode first.

### "DAG generation failed"
Not enough RAM for the DAG. Use regtest (16MB) or testnet (256MB).

### "RPC connection refused"
Make sure the node is running and `scrypt.conf` has `server=1`.

### Web apps show "Node connection failed"
The node isn't running or RPC credentials are wrong in the web app config.
