# Scrypt Coin (SCRYPT)

**A modern GPU-mineable cryptocurrency with adaptive memory growth**

Scrypt Coin combines the best innovations in cryptocurrency mining:
- **GPU-Mineable**: Shared DAG model allows efficient mining on modern GPUs
- **Adaptive Memory**: DAG size grows over time, keeping mining fair
- **ASIC-Resistant**: Random program execution prevents fixed-function hardware
- **Token Support**: Built-in support for creating custom tokens and NFTs

## Key Features

### AdaptivePow Algorithm
- Shared DAG stored in GPU memory (starts at 1 GB)
- DAG grows over time (doubles every ~2 years)
- Random math operations change each block
- Combines ideas from Ethash, KawPow, and YaCoin's N-factor

### Token System
- Create fungible tokens (like ERC-20)
- Create unique tokens/NFTs
- Sub-tokens and ownership tokens
- IPFS metadata support

### Technical Specifications

| Parameter | Value |
|-----------|-------|
| Block Time | 1 minute |
| Algorithm | AdaptivePow |
| Max Supply | 2 billion SCRYPT |
| Initial DAG | 1 GB |
| DAG Growth | Doubles every 4 epochs (~2 years) |
| Address Prefix | S (mainnet), s (testnet) |
| Default Port | 9333 |
| RPC Port | 9332 |

## Building

### Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential libtool autotools-dev automake pkg-config \
    bsdmainutils python3 libssl-dev libevent-dev libboost-all-dev \
    libminiupnpc-dev libzmq3-dev libqt5gui5 libqt5core5a libqt5dbus5 \
    qttools5-dev qttools5-dev-tools
```

**Windows:**
- Visual Studio 2022
- CUDA Toolkit 12.x (for GPU mining)

### Compile

```bash
./autogen.sh
./configure
make -j$(nproc)
```

### Cross-compile for Windows
```bash
cd depends
make HOST=x86_64-w64-mingw32
cd ..
./autogen.sh
./configure --prefix=`pwd`/depends/x86_64-w64-mingw32
make
```

## Running

### Start the node
```bash
./src/scryptd -daemon
```

### Using the CLI
```bash
./src/scrypt-cli getblockchaininfo
./src/scrypt-cli getmininginfo
```

### Configuration

Create `~/.scrypt/scrypt.conf`:
```
rpcuser=yourusername
rpcpassword=yourpassword
server=1
daemon=1
```

## Mining

### GPU Mining (Recommended)
Use the Scrypt GPU Miner for optimal performance:
```bash
./scrypt-miner -o stratum+tcp://pool.example.com:3333 -u WALLET -p x
```

Supported GPUs:
- NVIDIA RTX 20/30/40 series (CUDA)
- AMD RX 5000/6000/7000 series (OpenCL)

### Solo Mining
```bash
./scrypt-miner --solo -o http://127.0.0.1:9332 -u rpcuser -p rpcpass
```

## Tokens

### Create a Token
```bash
./scrypt-cli issue "MYTOKEN" 1000000
```

### Create an NFT
```bash
./scrypt-cli issue "MYTOKEN#unique_id" 1 "" 0 false true "QmIPFSHash"
```

### Transfer Tokens
```bash
./scrypt-cli transfer "MYTOKEN" 100 "SrecipientAddress"
```

## Development

### Running Tests
```bash
make check
./src/test/test_scrypt
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - see [COPYING](COPYING)

## Credits

Scrypt Coin builds upon:
- Bitcoin Core
- YaCoin (token system)
- Ethash (DAG concept)
- KawPow (random execution)
