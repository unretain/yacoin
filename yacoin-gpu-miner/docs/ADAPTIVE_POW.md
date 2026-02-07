# Adaptive Proof of Work (AdaptivePow)

A novel mining algorithm combining YaCoin's time-based memory scaling with GPU-friendly shared memory architecture.

## Overview

AdaptivePow is designed to be:
- **GPU-mineable** - Shared DAG model allows thousands of threads
- **ASIC-resistant** - Random program execution like KawPow
- **Future-proof** - Memory requirements grow over time (N-factor concept)
- **Fair** - Old hardware naturally phases out, preventing permanent dominance

## How It Differs

| Feature | YaCoin | Ethash | KawPow | AdaptivePow |
|---------|--------|--------|--------|-------------|
| Memory model | Per-thread | Shared DAG | Shared | Shared DAG |
| Memory growth | Yes (N-factor) | Fixed epochs | No | Yes (time-based) |
| GPU-friendly | No | Yes | Yes | Yes |
| ASIC-resistant | Yes | No | Yes | Yes |
| Random execution | No | No | Yes | Yes |

## Algorithm Specification

### 1. DAG Generation

The DAG (Directed Acyclic Graph) is a large dataset stored in GPU memory.

```
DAG_SIZE = BASE_SIZE * 2^(epoch / EPOCH_GROWTH_RATE)

Where:
  BASE_SIZE = 1 GB (1,073,741,824 bytes)
  EPOCH_GROWTH_RATE = 4 (size doubles every 4 epochs)
  epoch = (current_time - genesis_time) / EPOCH_LENGTH
  EPOCH_LENGTH = 180 days (approximately 6 months)
```

#### Growth Schedule

| Year | Epoch | DAG Size | Min GPU VRAM |
|------|-------|----------|--------------|
| 0    | 0-1   | 1 GB     | 2 GB         |
| 1    | 2-3   | 1-2 GB   | 3 GB         |
| 2    | 4-5   | 2 GB     | 4 GB         |
| 3    | 6-7   | 2-3 GB   | 4 GB         |
| 4    | 8-9   | 4 GB     | 6 GB         |
| 6    | 12-13 | 6 GB     | 8 GB         |
| 8    | 16-17 | 8 GB     | 12 GB        |
| 10   | 20-21 | 12 GB    | 16 GB        |
| 15   | 30-31 | 32 GB    | 48 GB        |

This is **much slower** than YaCoin's N-factor growth, giving hardware 4+ years of useful life.

#### DAG Generation Algorithm

```python
def generate_dag(epoch, dag_size):
    # Seed is deterministic from epoch
    seed = keccak256(epoch)

    # Generate cache (smaller, used to build DAG)
    cache_size = dag_size // 64
    cache = generate_cache(seed, cache_size)

    # Generate full DAG from cache
    dag = []
    for i in range(dag_size // HASH_BYTES):
        dag[i] = calc_dag_item(cache, i)

    return dag

def calc_dag_item(cache, index):
    # Mix cache elements based on index
    mix = cache[index % len(cache)]

    for round in range(DAG_ROUNDS):  # 256 rounds
        parent = fnv(index ^ round, mix[0]) % len(cache)
        mix = fnv_mix(mix, cache[parent])

    return keccak256(mix)
```

### 2. Mining (Hash Computation)

Each hash attempt:
1. Combines block header with nonce
2. Performs random DAG lookups
3. Executes random math operations (ASIC resistance)
4. Produces final hash

```python
def compute_hash(header, nonce, dag):
    # Initial seed from header + nonce
    seed = keccak512(header + nonce)

    # Initialize mix (256 bytes = 8 x 32-byte words)
    mix = [seed] * 8

    # Random DAG lookups + random math (64 rounds)
    for round in range(64):
        # Determine DAG index from mix
        dag_index = fnv(round, mix[round % 8]) % len(dag)

        # Fetch DAG data
        dag_data = dag[dag_index]

        # Random math operation (changes each block)
        mix = random_math(mix, dag_data, round, header)

    # Compress mix to 32 bytes
    result = compress(mix)

    # Final hash
    return keccak256(seed + result)

def random_math(mix, data, round, header):
    # Program seed from header (changes every block)
    prog_seed = fnv(header.height, header.hash[:4])

    # Select random operations based on prog_seed + round
    rng = kiss99(prog_seed ^ round)

    for i in range(MATH_OPS):  # 16 operations per round
        src1 = rng.next() % 8
        src2 = rng.next() % 8
        dst = rng.next() % 8
        op = rng.next() % 11

        # Operations: add, mul, sub, xor, rotate, etc.
        mix[dst] = apply_op(op, mix[src1], mix[src2], data)

    return mix
```

### 3. Verification

Verification is lightweight:
1. Regenerate seed from header + nonce
2. Perform same DAG lookups and math
3. Compare result against target

Verifiers need the DAG in memory OR can verify slowly by regenerating needed DAG items on-the-fly.

## Implementation Details

### Block Header Extension

```cpp
struct BlockHeader {
    int32_t  nVersion;
    uint256  hashPrevBlock;
    uint256  hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint64_t nNonce;          // Extended to 64-bit for GPUs
    uint256  mixHash;         // Mix digest for quick verification
};
```

### Epoch Calculation

```cpp
uint32_t get_epoch(uint64_t timestamp) {
    const uint64_t GENESIS_TIME = /* your genesis time */;
    const uint64_t EPOCH_LENGTH = 180 * 24 * 60 * 60;  // 180 days

    if (timestamp <= GENESIS_TIME) return 0;
    return (timestamp - GENESIS_TIME) / EPOCH_LENGTH;
}

uint64_t get_dag_size(uint32_t epoch) {
    const uint64_t BASE_SIZE = 1ULL << 30;  // 1 GB
    const uint32_t GROWTH_RATE = 4;          // Double every 4 epochs

    uint32_t doublings = epoch / GROWTH_RATE;
    return BASE_SIZE << doublings;
}
```

### GPU Memory Layout

```
GPU VRAM Layout:
┌────────────────────────────────────┐
│           DAG (shared)             │ ← 1-32 GB depending on epoch
├────────────────────────────────────┤
│        Header buffer               │ ← 80 bytes
├────────────────────────────────────┤
│        Output buffer               │ ← Results from threads
├────────────────────────────────────┤
│    Thread-local mix (registers)    │ ← 256 bytes per thread (in registers)
└────────────────────────────────────┘
```

## ASIC Resistance

Three layers of ASIC resistance:

### 1. Random Program Execution
- Math operations change every block
- Would require flexible ALU (essentially a GPU)

### 2. Memory Hardness
- Random DAG lookups require fast random access
- GPUs excel at this, fixed-function ASICs don't

### 3. Growing Memory
- DAG size increases over time
- ASICs with fixed memory become obsolete

## Comparison: Mining Efficiency

### YaCoin (Current)
```
GPU: RTX 4090 (24 GB VRAM)
Memory per thread: 128 MB (N-factor 19)
Max threads: 24 GB / 128 MB = 187 threads
Hashrate: ~200 H/s (estimated)
```

### AdaptivePow (Proposed)
```
GPU: RTX 4090 (24 GB VRAM)
DAG size: 4 GB (year 4)
Remaining VRAM: 20 GB for operations
Max threads: 20,000+ (limited by compute, not memory)
Hashrate: ~50 MH/s (estimated, depends on tuning)
```

**250,000x improvement** in thread count by using shared memory.

## Security Considerations

### 51% Attack Cost
- Requires controlling majority of GPU hashpower
- Growing DAG prevents single ASIC farm dominance
- Similar security model to Ethereum PoW era

### Light Client Verification
- Can verify without full DAG using cache
- Trade-off: slower verification, less memory
- Full nodes should keep DAG for fast verification

### DAG Predictability
- DAG is deterministic from epoch
- Can be pre-generated before epoch transition
- No advantage to pre-computation (still need hashpower)

## Migration Path

For existing YaCoin:

1. **Announce** - 6 months notice before activation
2. **Implement** - Add AdaptivePow code alongside Scrypt-Jane
3. **Activate** - At block height X, switch to AdaptivePow
4. **Grace period** - Accept both algorithms for 1000 blocks

## Naming Suggestion

**"ScryptDAG"** or **"AdaptiveDAG"** or **"TimeDAG"**

Reflects:
- Scrypt heritage (from YaCoin roots)
- DAG-based (shared memory)
- Time-adaptive (N-factor concept)

## Summary

AdaptivePow combines:
- YaCoin's **innovative time-based scaling**
- Ethash's **GPU-friendly shared DAG**
- KawPow's **ASIC-resistant random execution**

Result: A truly novel algorithm that is:
- Mineable on modern GPUs
- Resistant to ASICs
- Future-proof through memory growth
- Fair through hardware obsolescence
