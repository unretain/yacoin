# Scrypt Coin GPU Miner

GPU miner for Scrypt Coin's AdaptivePow algorithm.

## Features

- **CUDA support** for NVIDIA GPUs (RTX 20/30/40/50 series)
- **OpenCL support** for AMD GPUs (RX 5000/6000/7000/9000 series)
- **Stratum protocol** for pool mining
- **Solo mining** direct to node
- **Auto DAG generation** based on current epoch
- **Multi-GPU support**

## Algorithm: AdaptivePow

AdaptivePow combines:
- **Shared DAG** (like Ethash) - GPU-friendly, thousands of threads
- **Random execution** (like KawPow) - ASIC-resistant
- **Time-based memory growth** (like YaCoin N-factor) - Future-proof

### DAG Size Schedule

| Year | DAG Size | Min GPU VRAM |
|------|----------|--------------|
| 0    | 1 GB     | 2 GB         |
| 2    | 2 GB     | 4 GB         |
| 4    | 4 GB     | 6 GB         |
| 6    | 6 GB     | 8 GB         |

DAG doubles every 4 epochs (~2 years).

## Building

### Prerequisites

**Windows:**
- Visual Studio 2022
- CUDA Toolkit 12.x (for NVIDIA)
- AMD ROCm or OpenCL SDK (for AMD)

**Linux:**
```bash
sudo apt-get install build-essential cmake libssl-dev
# For NVIDIA: Install CUDA Toolkit
# For AMD: Install ROCm or AMDGPU-PRO drivers
```

### Compile

```bash
mkdir build && cd build

# NVIDIA (CUDA)
cmake .. -DWITH_CUDA=ON
make -j$(nproc)

# AMD (OpenCL)
cmake .. -DWITH_OPENCL=ON
make -j$(nproc)
```

## Usage

### Solo Mining (to your own node)

```bash
./scrypt-miner --solo \
  -o http://127.0.0.1:9332 \
  -u scryptrpc \
  -p yourpassword \
  --address SYourWalletAddress
```

### Pool Mining

```bash
./scrypt-miner \
  -o stratum+tcp://pool.scrypt.org:3333 \
  -u SYourWalletAddress \
  -p x
```

### Options

```
-d, --device      GPU device ID(s) to use (e.g., 0,1,2)
-i, --intensity   Mining intensity (8-25, default: auto)
-o, --url         Pool or node URL
-u, --user        RPC username or wallet address
-p, --pass        Password
--solo            Solo mining mode
--address         Payout address for solo mining
--benchmark       Run hashrate benchmark
--list-devices    Show available GPUs
```

## Expected Hashrates

| GPU | VRAM | Hashrate |
|-----|------|----------|
| RTX 4090 | 24 GB | ~50 MH/s |
| RTX 4080 | 16 GB | ~35 MH/s |
| RTX 3080 | 10 GB | ~30 MH/s |
| RX 7900 XTX | 24 GB | ~45 MH/s |
| RX 6800 XT | 16 GB | ~28 MH/s |

## Troubleshooting

- **"DAG generation failed"** - Not enough GPU VRAM
- **"Connection refused"** - Node not running or wrong RPC credentials
- **"GPU not found"** - Install CUDA/OpenCL drivers

## License

MIT License
