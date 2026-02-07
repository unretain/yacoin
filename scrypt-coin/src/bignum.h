// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2024-2026 The Scrypt Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Updated for OpenSSL 1.1+ compatibility (opaque BIGNUM)

#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include <stdexcept>
#include <vector>
#include <openssl/bn.h>
#include <openssl/opensslv.h>

#include "util.h"
#include "clientversion.h"
#include "serialize.h"
#include "uint256.h"

/** Errors thrown by the bignum class */
class bignum_error : public std::runtime_error
{
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};

/** RAII encapsulated BN_CTX (OpenSSL bignum context) */
class CAutoBN_CTX
{
protected:
    BN_CTX* pctx;
    BN_CTX* operator=(BN_CTX* pnew) { return pctx = pnew; }

public:
    CAutoBN_CTX()
    {
        pctx = BN_CTX_new();
        if (pctx == NULL)
            throw bignum_error("CAutoBN_CTX : BN_CTX_new() returned NULL");
    }

    ~CAutoBN_CTX()
    {
        if (pctx != NULL)
            BN_CTX_free(pctx);
    }

    operator BN_CTX*() { return pctx; }
    BN_CTX& operator*() { return *pctx; }
    BN_CTX** operator&() { return &pctx; }
    bool operator!() { return (pctx == NULL); }
};

/** C++ wrapper for BIGNUM (OpenSSL bignum) - Updated for OpenSSL 1.1+ */
class CBigNum
{
private:
    BIGNUM* bn;

    void init()
    {
        bn = BN_new();
        if (bn == NULL)
            throw bignum_error("CBigNum::init() : BN_new() failed");
    }

public:
    CBigNum()
    {
        init();
    }

    CBigNum(const CBigNum& b)
    {
        init();
        if (!BN_copy(bn, b.bn))
        {
            BN_free(bn);
            throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_copy failed");
        }
    }

    CBigNum& operator=(const CBigNum& b)
    {
        if (this != &b)
        {
            if (!BN_copy(bn, b.bn))
                throw bignum_error("CBigNum::operator= : BN_copy failed");
        }
        return *this;
    }

    ~CBigNum()
    {
        if (bn != NULL)
            BN_free(bn);
    }

    // Get pointer to underlying BIGNUM
    BIGNUM* get() { return bn; }
    const BIGNUM* get() const { return bn; }

    // Allow implicit conversion to BIGNUM* for compatibility
    operator BIGNUM*() { return bn; }
    operator const BIGNUM*() const { return bn; }

    CBigNum(int8_t n)  { init(); if (n >= 0) setuint32(n); else setint64(n); }
    CBigNum(int16_t n) { init(); if (n >= 0) setuint32(n); else setint64(n); }
    CBigNum(int32_t n) { init(); if (n >= 0) setuint32(n); else setint64(n); }
    CBigNum(int64_t n) { init(); setint64(n); }
    CBigNum(uint8_t n)  { init(); setuint32(n); }
    CBigNum(uint16_t n) { init(); setuint32(n); }
    CBigNum(uint32_t n) { init(); setuint32(n); }
    CBigNum(uint64_t n) { init(); setuint64(n); }
    explicit CBigNum(uint256 n) { init(); setuint256(n); }

    explicit CBigNum(const std::vector<unsigned char>& vch)
    {
        init();
        setvch(vch);
    }

    /** Generates a cryptographically secure random number between 0 and range-1 */
    static CBigNum randBignum(const CBigNum& range)
    {
        CBigNum ret;
        if (!BN_rand_range(ret.bn, range.bn))
            throw bignum_error("CBigNum::randBignum() : BN_rand_range failed");
        return ret;
    }

    /** Generates a random k-bit number */
    static CBigNum RandKBitBigum(uint32_t k)
    {
        CBigNum ret;
        if (!BN_rand(ret.bn, k, -1, 0))
            throw bignum_error("CBigNum::RandKBitBigum() : BN_rand failed");
        return ret;
    }

    int bitSize() const
    {
        return BN_num_bits(bn);
    }

    void setuint32(uint32_t n)
    {
        if (!BN_set_word(bn, n))
            throw bignum_error("CBigNum::setuint32() : BN_set_word failed");
    }

    uint32_t getuint32() const
    {
        return BN_get_word(bn);
    }

    int32_t getint32() const
    {
        uint32_t n = BN_get_word(bn);
        if (!BN_is_negative(bn))
            return (n > (uint32_t)std::numeric_limits<int32_t>::max() ? std::numeric_limits<int32_t>::max() : (int32_t)n);
        else
            return (n > (uint32_t)std::numeric_limits<int32_t>::max() ? std::numeric_limits<int32_t>::min() : -(int32_t)n);
    }

    void setint64(int64_t sn)
    {
        unsigned char pch[sizeof(sn) + 6];
        unsigned char* p = pch + 4;
        bool fNegative = sn < 0;
        uint64_t n = fNegative ? -sn : sn;
        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            unsigned char c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = (fNegative ? 0x80 : 0);
                else if (fNegative)
                    c |= 0x80;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        uint32_t nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, bn);
    }

    void setuint64(uint64_t n)
    {
        // Use BN_set_word if it fits, otherwise use MPI
        if (sizeof(unsigned long) >= sizeof(uint64_t))
        {
            if (!BN_set_word(bn, (BN_ULONG)n))
                throw bignum_error("CBigNum::setuint64() : BN_set_word failed");
            return;
        }

        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            unsigned char c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        uint32_t nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, bn);
    }

    uint64_t getuint64() const
    {
        size_t nSize = BN_bn2mpi(bn, NULL);
        if (nSize < 4)
            return 0;
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(bn, &vch[0]);
        if (vch.size() > 4)
            vch[4] &= 0x7f;
        uint64_t n = 0;
        for (size_t i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            ((unsigned char*)&n)[i] = vch[j];
        return n;
    }

    void setuint256(uint256 n)
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fLeadingZeroes = true;
        unsigned char* pbegin = (unsigned char*)&n;
        unsigned char* psrc = pbegin + sizeof(n);
        while (psrc != pbegin)
        {
            unsigned char c = *(--psrc);
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        uint32_t nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, bn);
    }

    uint256 getuint256() const
    {
        unsigned int nSize = BN_bn2mpi(bn, NULL);
        if (nSize < 4)
            return uint256();
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(bn, &vch[0]);
        if (vch.size() > 4)
            vch[4] &= 0x7f;
        uint256 n;
        for (size_t i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            ((unsigned char*)&n)[i] = vch[j];
        return n;
    }

    void setvch(const std::vector<unsigned char>& vch)
    {
        std::vector<unsigned char> vch2(vch.size() + 4);
        uint32_t nSize = vch.size();
        vch2[0] = (nSize >> 24) & 0xff;
        vch2[1] = (nSize >> 16) & 0xff;
        vch2[2] = (nSize >> 8) & 0xff;
        vch2[3] = (nSize >> 0) & 0xff;
        std::reverse_copy(vch.begin(), vch.end(), vch2.begin() + 4);
        BN_mpi2bn(&vch2[0], vch2.size(), bn);
    }

    std::vector<unsigned char> getvch() const
    {
        unsigned int nSize = BN_bn2mpi(bn, NULL);
        if (nSize <= 4)
            return std::vector<unsigned char>();
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(bn, &vch[0]);
        vch.erase(vch.begin(), vch.begin() + 4);
        std::reverse(vch.begin(), vch.end());
        return vch;
    }

    CBigNum& SetCompact(uint32_t nCompact)
    {
        unsigned int nSize = nCompact >> 24;
        std::vector<unsigned char> vch(4 + nSize);
        vch[3] = nSize;
        if (nSize >= 1) vch[4] = (nCompact >> 16) & 0xff;
        if (nSize >= 2) vch[5] = (nCompact >> 8) & 0xff;
        if (nSize >= 3) vch[6] = (nCompact >> 0) & 0xff;
        BN_mpi2bn(&vch[0], vch.size(), bn);
        return *this;
    }

    uint32_t GetCompact() const
    {
        unsigned int nSize = BN_bn2mpi(bn, NULL);
        std::vector<unsigned char> vch(nSize);
        nSize -= 4;
        BN_bn2mpi(bn, &vch[0]);
        uint32_t nCompact = nSize << 24;
        if (nSize >= 1) nCompact |= (vch[4] << 16);
        if (nSize >= 2) nCompact |= (vch[5] << 8);
        if (nSize >= 3) nCompact |= (vch[6] << 0);
        return nCompact;
    }

    void SetHex(const std::string& str)
    {
        const char* psz = str.c_str();
        while (isspace(*psz)) psz++;
        bool fNegative = false;
        if (*psz == '-') { fNegative = true; psz++; }
        if (psz[0] == '0' && tolower(psz[1]) == 'x') psz += 2;
        while (isspace(*psz)) psz++;

        static const signed char phexdigit[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
            -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        };

        *this = 0;
        while (phexdigit[(unsigned char)*psz] >= 0)
        {
            *this <<= 4;
            int n = phexdigit[(unsigned char)*psz++];
            *this += n;
        }
        if (fNegative)
            BN_set_negative(bn, 1);
    }

    std::string ToString(int nBase=10) const
    {
        CAutoBN_CTX pctx;
        CBigNum bnBase(nBase);
        CBigNum bn0(0);
        std::string str;
        CBigNum bnCopy = *this;
        BN_set_negative(bnCopy.bn, false);
        CBigNum dv, rem;
        if (BN_cmp(bnCopy.bn, bn0.bn) == 0)
            return "0";
        while (BN_cmp(bnCopy.bn, bn0.bn) > 0)
        {
            if (!BN_div(dv.bn, rem.bn, bnCopy.bn, bnBase.bn, pctx))
                throw bignum_error("CBigNum::ToString() : BN_div failed");
            bnCopy = dv;
            uint32_t c = rem.getuint32();
            str += "0123456789abcdef"[c];
        }
        if (BN_is_negative(bn))
            str += "-";
        std::reverse(str.begin(), str.end());
        return str;
    }

    std::string GetHex() const { return ToString(16); }

    bool operator!() const { return BN_is_zero(bn); }

    CBigNum& operator+=(const CBigNum& b)
    {
        if (!BN_add(bn, bn, b.bn))
            throw bignum_error("CBigNum::operator+= : BN_add failed");
        return *this;
    }

    CBigNum& operator-=(const CBigNum& b)
    {
        if (!BN_sub(bn, bn, b.bn))
            throw bignum_error("CBigNum::operator-= : BN_sub failed");
        return *this;
    }

    CBigNum& operator*=(const CBigNum& b)
    {
        CAutoBN_CTX pctx;
        if (!BN_mul(bn, bn, b.bn, pctx))
            throw bignum_error("CBigNum::operator*= : BN_mul failed");
        return *this;
    }

    CBigNum& operator/=(const CBigNum& b)
    {
        CAutoBN_CTX pctx;
        if (!BN_div(bn, NULL, bn, b.bn, pctx))
            throw bignum_error("CBigNum::operator/= : BN_div failed");
        return *this;
    }

    CBigNum& operator%=(const CBigNum& b)
    {
        CAutoBN_CTX pctx;
        if (!BN_mod(bn, bn, b.bn, pctx))
            throw bignum_error("CBigNum::operator%= : BN_mod failed");
        return *this;
    }

    CBigNum& operator<<=(unsigned int shift)
    {
        if (!BN_lshift(bn, bn, shift))
            throw bignum_error("CBigNum::operator<<= : BN_lshift failed");
        return *this;
    }

    CBigNum& operator>>=(unsigned int shift)
    {
        CBigNum a(1);
        a <<= shift;
        if (BN_cmp(a.bn, bn) > 0)
        {
            *this = 0;
            return *this;
        }
        if (!BN_rshift(bn, bn, shift))
            throw bignum_error("CBigNum::operator>>= : BN_rshift failed");
        return *this;
    }

    CBigNum& operator++()
    {
        if (!BN_add(bn, bn, BN_value_one()))
            throw bignum_error("CBigNum::operator++ : BN_add failed");
        return *this;
    }

    const CBigNum operator++(int)
    {
        const CBigNum ret = *this;
        ++(*this);
        return ret;
    }

    CBigNum& operator--()
    {
        CBigNum r;
        if (!BN_sub(r.bn, bn, BN_value_one()))
            throw bignum_error("CBigNum::operator-- : BN_sub failed");
        *this = r;
        return *this;
    }

    const CBigNum operator--(int)
    {
        const CBigNum ret = *this;
        --(*this);
        return ret;
    }

    friend inline const CBigNum operator+(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator-(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator-(const CBigNum& a);
    friend inline const CBigNum operator*(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator/(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator%(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator<<(const CBigNum& a, unsigned int shift);
    friend inline bool operator==(const CBigNum& a, const CBigNum& b);
    friend inline bool operator!=(const CBigNum& a, const CBigNum& b);
    friend inline bool operator<=(const CBigNum& a, const CBigNum& b);
    friend inline bool operator>=(const CBigNum& a, const CBigNum& b);
    friend inline bool operator<(const CBigNum& a, const CBigNum& b);
    friend inline bool operator>(const CBigNum& a, const CBigNum& b);
};

inline const CBigNum operator+(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_add(r.bn, a.bn, b.bn))
        throw bignum_error("CBigNum::operator+ : BN_add failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_sub(r.bn, a.bn, b.bn))
        throw bignum_error("CBigNum::operator- : BN_sub failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a)
{
    CBigNum r(a);
    BN_set_negative(r.bn, !BN_is_negative(r.bn));
    return r;
}

inline const CBigNum operator*(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_mul(r.bn, a.bn, b.bn, pctx))
        throw bignum_error("CBigNum::operator* : BN_mul failed");
    return r;
}

inline const CBigNum operator/(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_div(r.bn, NULL, a.bn, b.bn, pctx))
        throw bignum_error("CBigNum::operator/ : BN_div failed");
    return r;
}

inline const CBigNum operator%(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_nnmod(r.bn, a.bn, b.bn, pctx))
        throw bignum_error("CBigNum::operator% : BN_nnmod failed");
    return r;
}

inline const CBigNum operator<<(const CBigNum& a, unsigned int shift)
{
    CBigNum r;
    if (!BN_lshift(r.bn, a.bn, shift))
        throw bignum_error("CBigNum::operator<< : BN_lshift failed");
    return r;
}

inline bool operator==(const CBigNum& a, const CBigNum& b) { return BN_cmp(a.bn, b.bn) == 0; }
inline bool operator!=(const CBigNum& a, const CBigNum& b) { return BN_cmp(a.bn, b.bn) != 0; }
inline bool operator<=(const CBigNum& a, const CBigNum& b) { return BN_cmp(a.bn, b.bn) <= 0; }
inline bool operator>=(const CBigNum& a, const CBigNum& b) { return BN_cmp(a.bn, b.bn) >= 0; }
inline bool operator<(const CBigNum& a, const CBigNum& b)  { return BN_cmp(a.bn, b.bn) < 0; }
inline bool operator>(const CBigNum& a, const CBigNum& b)  { return BN_cmp(a.bn, b.bn) > 0; }

#endif // BITCOIN_BIGNUM_H
