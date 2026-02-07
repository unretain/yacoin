// Genesis Block Miner for Scrypt Coin
// Compile and run this standalone to find the genesis block
// Then update chainparams.cpp with the results

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <openssl/sha.h>

// Simple SHA256 for genesis mining
void sha256(const void* data, size_t len, unsigned char* out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out, &ctx);
}

void double_sha256(const void* data, size_t len, unsigned char* out) {
    unsigned char tmp[32];
    sha256(data, len, tmp);
    sha256(tmp, 32, out);
}

// Check if hash meets target (simplified)
bool check_pow(unsigned char* hash, uint32_t nBits) {
    // For 0x1e0fffff, first byte should be 0x00, and hash should be small
    // This is a simplified check - first 3 bytes should be zero
    return hash[31] == 0 && hash[30] == 0 && hash[29] == 0;
}

void print_hash(unsigned char* hash) {
    for (int i = 31; i >= 0; i--) {
        printf("%02x", hash[i]);
    }
}

#pragma pack(push, 1)
struct BlockHeader {
    int32_t nVersion;
    unsigned char hashPrevBlock[32];
    unsigned char hashMerkleRoot[32];
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
};
#pragma pack(pop)

int main() {
    printf("===========================================\n");
    printf("  SCRYPT COIN GENESIS BLOCK MINER\n");
    printf("===========================================\n\n");

    const char* pszTimestamp = "Scrypt Coin Launch - GPU Mining for Everyone - Feb 2026";
    uint32_t nTime = 1738886400;  // Feb 7, 2026 00:00:00 UTC
    uint32_t nBits = 0x1e0fffff;

    printf("Timestamp: %s\n", pszTimestamp);
    printf("Time: %u\n", nTime);
    printf("Bits: 0x%08x\n\n", nBits);

    // Create coinbase transaction hash (simplified - just hash the timestamp)
    unsigned char txHash[32];
    sha256(pszTimestamp, strlen(pszTimestamp), txHash);

    // Merkle root is just the coinbase tx hash for genesis
    unsigned char merkleRoot[32];
    memcpy(merkleRoot, txHash, 32);

    printf("Merkle Root: ");
    print_hash(merkleRoot);
    printf("\n\n");

    // Create block header
    BlockHeader header;
    header.nVersion = 1;
    memset(header.hashPrevBlock, 0, 32);
    memcpy(header.hashMerkleRoot, merkleRoot, 32);
    header.nTime = nTime;
    header.nBits = nBits;
    header.nNonce = 0;

    printf("Mining genesis block...\n");
    printf("This may take a few minutes.\n\n");

    unsigned char hash[32];
    uint64_t attempts = 0;
    time_t startTime = time(NULL);

    while (true) {
        double_sha256(&header, sizeof(header), hash);

        if (check_pow(hash, nBits)) {
            printf("\n===========================================\n");
            printf("  GENESIS BLOCK FOUND!\n");
            printf("===========================================\n\n");
            printf("nNonce: %u\n", header.nNonce);
            printf("Hash: ");
            print_hash(hash);
            printf("\n\n");

            printf("Update chainparams.cpp with:\n\n");
            printf("static uint256 hashGenesisBlock = uint256S(\"0x");
            print_hash(hash);
            printf("\");\n");
            printf("static uint32_t nGenesisNonce = %u;\n", header.nNonce);
            printf("static uint256 hashGenesisMerkleRoot = uint256S(\"0x");
            print_hash(merkleRoot);
            printf("\");\n\n");

            break;
        }

        header.nNonce++;
        attempts++;

        if (attempts % 1000000 == 0) {
            time_t now = time(NULL);
            double elapsed = difftime(now, startTime);
            double rate = attempts / (elapsed > 0 ? elapsed : 1);
            printf("Attempts: %llu, Rate: %.0f H/s, Nonce: %u\n",
                   (unsigned long long)attempts, rate, header.nNonce);
        }

        if (header.nNonce == 0xFFFFFFFF) {
            printf("Nonce space exhausted. Try different timestamp.\n");
            break;
        }
    }

    return 0;
}
