# YaCoin GPU Miner

A modern GPU miner for YaCoin's Scrypt-Jane (ChaCha20/8) algorithm with variable N-factor support.

## Features

- **CUDA support** for NVIDIA GPUs (RTX 20/30/40 series)
- **OpenCL support** for AMD GPUs (RX 5000/6000/7000 series)
- **Stratum protocol** for pool mining
- **Solo mining** direct to node
- **Auto N-factor detection** from network
- **Multi-GPU support**

## Algorithm

YaCoin uses Scrypt-Jane with:
- Mixing function: ChaCha20/8
- Variable N-factor (increases over time)
- r = 1, p = 1
- Memory per thread: `(N + 2) * 128` bytes where `N = 2^(Nfactor+1)`

### Current N-factor

As of 2026, N-factor is approximately 19-20, meaning:
- N = 2^20 to 2^21 = 1M to 2M iterations
- Memory per thread: ~128MB to ~256MB

## Building

### Prerequisites

**Windows:**
- Visual Studio 2022
- CUDA Toolkit 12.x (for NVIDIA)
- AMD ROCm or AMD APP SDK (for AMD)

**Linux:**
- GCC 11+
- CUDA Toolkit 12.x
- OpenCL headers and drivers

### Compile

```bash
# NVIDIA (CUDA)
mkdir build && cd build
cmake .. -DWITH_CUDA=ON
make -j$(nproc)

# AMD (OpenCL)
mkdir build && cd build
cmake .. -DWITH_OPENCL=ON
make -j$(nproc)
```

## Usage

### Pool Mining (Stratum)
```bash
./yacminer -o stratum+tcp://pool.example.com:3333 -u wallet_address -p x
```

### Solo Mining
```bash
./yacminer --solo -o http://127.0.0.1:7688 -u rpcuser -p rpcpassword
```

### Options
```
-d, --device      GPU device ID(s) to use (e.g., 0,1,2)
-i, --intensity   Mining intensity (8-25, default: auto)
-o, --url         Pool/node URL
-u, --user        Username/wallet
-p, --pass        Password
--solo            Solo mining mode
--benchmark       Run benchmark
```

## Architecture

```
src/
├── core/           # Common code
│   ├── miner.cpp   # Main mining loop
│   ├── stratum.cpp # Stratum protocol
│   └── util.cpp    # Utilities
├── cuda/           # NVIDIA implementation
│   ├── scrypt_jane.cu
│   └── chacha.cu
└── opencl/         # AMD implementation
    ├── scrypt_jane.cl
    └── chacha.cl
```

## License

MIT License
