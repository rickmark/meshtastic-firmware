// OpenSSL-backed crypto hooks so PresenceCore can run on the host.
#include "../../src/modules/optional/HotMessPresence/PresenceCore.h"
#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdexcept>

namespace hmp
{
static_assert(sizeof(SHA256_CTX) <= sizeof(Sha256Ctx::opaque), "ctx");
void sha256Begin(Sha256Ctx &c) { SHA256_Init(reinterpret_cast<SHA256_CTX *>(c.opaque)); }
void sha256Update(Sha256Ctx &c, const void *d, size_t n) { SHA256_Update(reinterpret_cast<SHA256_CTX *>(c.opaque), d, n); }
void sha256Final(Sha256Ctx &c, uint8_t out[32]) { SHA256_Final(out, reinterpret_cast<SHA256_CTX *>(c.opaque)); }

bool ed25519Verify(const uint8_t sig[64], const uint8_t pub[32], const uint8_t *msg, size_t len)
{
    EVP_PKEY *k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub, 32);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    bool ok = EVP_DigestVerifyInit(m, nullptr, nullptr, nullptr, k) == 1 && EVP_DigestVerify(m, sig, 64, msg, len) == 1;
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(k);
    return ok;
}
void ed25519Sign(uint8_t sig[64], const uint8_t priv[32], const uint8_t *, const uint8_t *msg, size_t len)
{
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv, 32);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    size_t sl = 64;
    if (EVP_DigestSignInit(m, nullptr, nullptr, nullptr, k) != 1 || EVP_DigestSign(m, sig, &sl, msg, len) != 1)
        throw std::runtime_error("sign");
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(k);
}
void ed25519DerivePublic(uint8_t pub[32], const uint8_t priv[32])
{
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv, 32);
    size_t l = 32;
    EVP_PKEY_get_raw_public_key(k, pub, &l);
    EVP_PKEY_free(k);
}
} // namespace hmp
