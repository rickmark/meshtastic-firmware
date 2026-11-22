// Crypto hooks for PresenceCore on the beacon, backed by the Crypto library Meshtastic already links.
#include "configuration.h"

#if defined(ARCH_NRF52) && !defined(ARCH_NRF54L)
#include "PresenceCore.h"
#include <Ed25519.h>
#include <SHA256.h>
#include <new>

namespace hmp
{

static_assert(sizeof(SHA256) <= sizeof(Sha256Ctx::opaque), "Sha256Ctx too small for SHA256");

static SHA256 &obj(Sha256Ctx &ctx)
{
    return *reinterpret_cast<SHA256 *>(ctx.opaque);
}

void sha256Begin(Sha256Ctx &ctx)
{
    new (ctx.opaque) SHA256();
}

void sha256Update(Sha256Ctx &ctx, const void *data, size_t len)
{
    obj(ctx).update(data, len);
}

void sha256Final(Sha256Ctx &ctx, uint8_t out[32])
{
    obj(ctx).finalize(out, 32);
    obj(ctx).~SHA256(); // clears the state
}

bool ed25519Verify(const uint8_t sig[64], const uint8_t pub[32], const uint8_t *msg, size_t len)
{
    return Ed25519::verify(sig, pub, msg, len);
}

void ed25519Sign(uint8_t sig[64], const uint8_t priv[32], const uint8_t pub[32], const uint8_t *msg, size_t len)
{
    Ed25519::sign(sig, priv, pub, msg, len);
}

void ed25519DerivePublic(uint8_t pub[32], const uint8_t priv[32])
{
    Ed25519::derivePublicKey(pub, priv);
}

} // namespace hmp
#endif
