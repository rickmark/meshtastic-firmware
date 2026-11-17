#ifndef HMP_HOST_TEST
#include "configuration.h"
#endif
#if defined(HMP_HOST_TEST) || (defined(ARCH_NRF52) && !defined(ARCH_NRF54L))
#include "PresenceCore.h"
#include <cmath>
#include <cstdlib>
#include <cstring>

namespace hmp
{

void sha256(const void *data, size_t len, uint8_t out[32])
{
    Sha256Ctx ctx;
    sha256Begin(ctx);
    sha256Update(ctx, data, len);
    sha256Final(ctx, out);
}

void hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *msg, size_t msgLen, uint8_t out[32])
{
    uint8_t k[64] = {0};
    if (keyLen > 64)
        sha256(key, keyLen, k);
    else
        memcpy(k, key, keyLen);
    uint8_t pad[64];
    uint8_t inner[32];
    Sha256Ctx ctx;
    for (int i = 0; i < 64; i++)
        pad[i] = k[i] ^ 0x36;
    sha256Begin(ctx);
    sha256Update(ctx, pad, 64);
    sha256Update(ctx, msg, msgLen);
    sha256Final(ctx, inner);
    for (int i = 0; i < 64; i++)
        pad[i] = k[i] ^ 0x5c;
    sha256Begin(ctx);
    sha256Update(ctx, pad, 64);
    sha256Update(ctx, inner, 32);
    sha256Final(ctx, out);
}

// ---------------------------------------------------------------- params

void defaultParams(Params &p)
{
    memset(&p, 0, sizeof(p));
    p.tickMs = 30000;
    p.chainLength = 1051200; // one year of 30 s ticks
    p.chainValueLen = 16;
    p.checkpointInterval = 4096;
    p.hmacLen = 8;
    p.totpStepS = 30;
    p.totpDigits = 8;
    p.schemeMask = SCHEME_CHAIN | SCHEME_HMAC | SCHEME_TOTP;
    p.weightPresence = 3;
    p.weightIBeacon = 1;
    p.weightEddystone = 1;
    p.statusEvery = 10;
    p.slotMs = 1000;
    p.advIntervalMs = 100;
    p.addressRotateSlots = 1;
    p.theftRadiusM = 200;
    p.theftCheckS = 300;
    p.theftReportS = 900;
    p.theftConfirmFixes = 3;
    p.persistEveryTicks = 20;
    p.windowBackTicks = 4;
    p.windowFwdTicks = 1;
    p.fwHashLen = 8;
    p.keyFpLen = 4;
    p.companyId = 0xFFFF; // Bluetooth SIG "test" id until a real one is assigned
    p.txPowerDbm = 0;
    p.iBeaconMajor = 1;
    p.iBeaconMinor = 0;
    // 5a51609d-ede0-497f-8b3c-98d031d136e8: Hot Mess pilot iBeacon UUID
    static const uint8_t uuid[16] = {0x5a, 0x51, 0x60, 0x9d, 0xed, 0xe0, 0x49, 0x7f,
                                     0x8b, 0x3c, 0x98, 0xd0, 0x31, 0xd1, 0x36, 0xe8};
    memcpy(p.iBeaconUuid, uuid, 16);
    memcpy(p.eddystoneNamespace, uuid, 10);
    p.totpWindowSteps = 1;
    p.chainGenBatch = 2048;
    p.checkpointRamMax = 8192;
    p.bootReportDelayS = 60;
}

static uint32_t *u32Field(Params &p, uint8_t id)
{
    switch (id) {
    case P_TICK_MS:
        return &p.tickMs;
    case P_CHAIN_LENGTH:
        return &p.chainLength;
    case P_CHAIN_VALUE_LEN:
        return &p.chainValueLen;
    case P_CHECKPOINT_INTERVAL:
        return &p.checkpointInterval;
    case P_HMAC_LEN:
        return &p.hmacLen;
    case P_TOTP_STEP_S:
        return &p.totpStepS;
    case P_TOTP_DIGITS:
        return &p.totpDigits;
    case P_SCHEME_MASK:
        return &p.schemeMask;
    case P_WEIGHT_PRESENCE:
        return &p.weightPresence;
    case P_WEIGHT_IBEACON:
        return &p.weightIBeacon;
    case P_WEIGHT_EDDYSTONE:
        return &p.weightEddystone;
    case P_STATUS_EVERY:
        return &p.statusEvery;
    case P_SLOT_MS:
        return &p.slotMs;
    case P_ADV_INTERVAL_MS:
        return &p.advIntervalMs;
    case P_ADDRESS_ROTATE_SLOTS:
        return &p.addressRotateSlots;
    case P_THEFT_RADIUS_M:
        return &p.theftRadiusM;
    case P_THEFT_CHECK_S:
        return &p.theftCheckS;
    case P_THEFT_REPORT_S:
        return &p.theftReportS;
    case P_THEFT_CONFIRM_FIXES:
        return &p.theftConfirmFixes;
    case P_PERSIST_EVERY_TICKS:
        return &p.persistEveryTicks;
    case P_WINDOW_BACK_TICKS:
        return &p.windowBackTicks;
    case P_WINDOW_FWD_TICKS:
        return &p.windowFwdTicks;
    case P_FW_HASH_LEN:
        return &p.fwHashLen;
    case P_KEY_FP_LEN:
        return &p.keyFpLen;
    case P_COMPANY_ID:
        return &p.companyId;
    case P_TX_POWER_DBM:
        return reinterpret_cast<uint32_t *>(&p.txPowerDbm);
    case P_IBEACON_MAJOR:
        return &p.iBeaconMajor;
    case P_IBEACON_MINOR:
        return &p.iBeaconMinor;
    case P_TOTP_WINDOW_STEPS:
        return &p.totpWindowSteps;
    case P_CHAIN_GEN_BATCH:
        return &p.chainGenBatch;
    case P_CHECKPOINT_RAM_MAX:
        return &p.checkpointRamMax;
    case P_BOOT_REPORT_DELAY_S:
        return &p.bootReportDelayS;
    default:
        return nullptr;
    }
}

static uint8_t *bytesField(Params &p, uint8_t id, size_t &len)
{
    switch (id) {
    case P_IBEACON_UUID:
        len = 16;
        return p.iBeaconUuid;
    case P_EDDYSTONE_NAMESPACE:
        len = 10;
        return p.eddystoneNamespace;
    case P_EDDYSTONE_INSTANCE:
        len = 6;
        return p.eddystoneInstance;
    default:
        return nullptr;
    }
}

bool validateParams(const Params &p)
{
    if (p.tickMs < 1000 || p.slotMs < 100 || p.advIntervalMs < 20 || p.advIntervalMs > 10240)
        return false;
    if (p.chainValueLen < 8 || p.chainValueLen > 32 || p.chainLength < 2 || p.checkpointInterval < 1)
        return false;
    if (FRAME_HEADER_LEN + p.chainValueLen > FRAME_MAX)
        return false;
    uint64_t cps = (uint64_t)p.chainLength / p.checkpointInterval + 1;
    if (cps * p.chainValueLen > p.checkpointRamMax)
        return false;
    if (p.hmacLen < 4 || p.hmacLen > 32 || FRAME_HEADER_LEN + p.hmacLen > FRAME_MAX)
        return false;
    if (p.totpStepS < 1 || p.totpDigits < 6 || p.totpDigits > 9)
        return false;
    if ((p.schemeMask & ~7u) != 0 || p.companyId > 0xFFFF || p.iBeaconMajor > 0xFFFF || p.iBeaconMinor > 0xFFFF)
        return false;
    if (FRAME_HEADER_LEN + 3 + p.fwHashLen + p.keyFpLen > FRAME_MAX || p.fwHashLen > 32 || p.keyFpLen > 32)
        return false;
    if (p.addressRotateSlots < 1 || p.persistEveryTicks < 1 || p.chainGenBatch < 1 || p.theftConfirmFixes < 1)
        return false;
    if (p.txPowerDbm < -40 || p.txPowerDbm > 8)
        return false;
    return true;
}

bool applyParamTlv(Params &p, const uint8_t *tlv, size_t len)
{
    Params next = p;
    size_t i = 0;
    while (i < len) {
        if (i + 2 > len)
            return false;
        uint8_t id = tlv[i], l = tlv[i + 1];
        const uint8_t *v = tlv + i + 2;
        if (i + 2 + l > len)
            return false;
        size_t blen = 0;
        uint8_t *b = bytesField(next, id, blen);
        uint32_t *u = u32Field(next, id);
        if (b) {
            if (l != blen)
                return false;
            memcpy(b, v, blen);
        } else if (u) {
            if (l < 1 || l > 4)
                return false;
            uint32_t x = 0;
            for (uint8_t j = 0; j < l; j++)
                x = (x << 8) | v[j];
            if (id == P_TX_POWER_DBM && l < 4 && (v[0] & 0x80)) // sign-extend short negative values
                x |= ~0u << (8 * l);
            *u = x;
        } else {
            return false;
        }
        i += 2 + l;
    }
    if (!validateParams(next))
        return false;
    p = next;
    return true;
}

size_t encodeParamTlv(const Params &pin, uint8_t *out, size_t cap)
{
    Params p = pin;
    size_t o = 0;
    for (uint8_t id = 1; id <= P_MAX_ID; id++) {
        size_t blen = 0;
        uint8_t *b = bytesField(p, id, blen);
        uint32_t *u = u32Field(p, id);
        size_t l = b ? blen : 4;
        if (o + 2 + l > cap)
            return 0;
        out[o] = id;
        out[o + 1] = (uint8_t)l;
        if (b)
            memcpy(out + o + 2, b, blen);
        else
            putU32(out + o + 2, *u);
        o += 2 + l;
    }
    return o;
}

// ---------------------------------------------------------------- frames

static void putHeader(uint8_t *out, uint8_t kind, uint32_t beaconId, uint32_t epochId, uint32_t position)
{
    out[0] = (uint8_t)((FRAME_VERSION << 4) | (kind & 0x0F));
    putU32(out + 1, beaconId);
    putU16(out + 5, (uint16_t)epochId);
    putU32(out + 7, position);
}

size_t encodePresenceFrame(uint8_t *out, uint8_t kind, uint32_t beaconId, uint32_t epochId, uint32_t position,
                           const uint8_t *token, size_t tokenLen)
{
    if (FRAME_HEADER_LEN + tokenLen > FRAME_MAX)
        return 0;
    putHeader(out, kind, beaconId, epochId, position);
    memcpy(out + FRAME_HEADER_LEN, token, tokenLen);
    return FRAME_HEADER_LEN + tokenLen;
}

size_t encodeStatusFrame(uint8_t *out, uint32_t beaconId, uint32_t epochId, const uint8_t fwVersion[3], const uint8_t *fwHash,
                         size_t fwHashLen, const uint8_t *keyFp, size_t keyFpLen)
{
    size_t total = FRAME_HEADER_LEN + 3 + fwHashLen + keyFpLen;
    if (total > FRAME_MAX)
        return 0;
    putHeader(out, KIND_STATUS, beaconId, epochId, 0);
    memcpy(out + FRAME_HEADER_LEN, fwVersion, 3);
    memcpy(out + FRAME_HEADER_LEN + 3, fwHash, fwHashLen);
    memcpy(out + FRAME_HEADER_LEN + 3 + fwHashLen, keyFp, keyFpLen);
    return total;
}

// ---------------------------------------------------------------- hash chain

void chainSeedToX0(const uint8_t seed[32], uint32_t valueLen, uint8_t *out)
{
    uint8_t h[32];
    Sha256Ctx ctx;
    sha256Begin(ctx);
    sha256Update(ctx, "HMPC-seed", 9);
    sha256Update(ctx, seed, 32);
    sha256Final(ctx, h);
    memcpy(out, h, valueLen);
}

void chainStep(const uint8_t *in, uint32_t valueLen, uint8_t *out)
{
    uint8_t h[32];
    Sha256Ctx ctx;
    sha256Begin(ctx);
    sha256Update(ctx, "HMPC", 4);
    sha256Update(ctx, in, valueLen);
    sha256Final(ctx, h);
    memcpy(out, h, valueLen);
}

HashChain::~HashChain()
{
    clear();
}

void HashChain::clear()
{
    if (checkpoints) {
        memset(checkpoints, 0, (size_t)(n / k + 1) * len);
        free(checkpoints);
    }
    checkpoints = nullptr;
    memset(cursor, 0, sizeof(cursor));
    memset(anchorValue, 0, sizeof(anchorValue));
    state = EMPTY;
}

bool HashChain::begin(const uint8_t seed[32], uint32_t chainLength, uint32_t valueLen, uint32_t checkpointInterval,
                      uint32_t ramMax)
{
    clear();
    if (valueLen < 8 || valueLen > 32 || chainLength < 2 || checkpointInterval < 1)
        return false;
    uint64_t bytes = ((uint64_t)chainLength / checkpointInterval + 1) * valueLen;
    if (bytes > ramMax)
        return false;
    checkpoints = (uint8_t *)malloc((size_t)bytes);
    if (!checkpoints)
        return false;
    n = chainLength;
    len = valueLen;
    k = checkpointInterval;
    chainSeedToX0(seed, len, cursor);
    memcpy(checkpoints, cursor, len);
    nextIndex = 1;
    state = GENERATING;
    return true;
}

bool HashChain::generate(uint32_t maxSteps)
{
    if (state != GENERATING)
        return state == READY;
    while (maxSteps-- && nextIndex <= n) {
        chainStep(cursor, len, cursor);
        if (nextIndex % k == 0)
            memcpy(checkpoints + (size_t)(nextIndex / k) * len, cursor, len);
        nextIndex++;
    }
    if (nextIndex > n) {
        memcpy(anchorValue, cursor, len);
        memset(cursor, 0, sizeof(cursor));
        state = READY;
    }
    return state == READY;
}

bool HashChain::valueAtTick(uint32_t t, uint8_t *out) const
{
    if (state != READY || t < 1 || t > n)
        return false;
    uint32_t index = n - t;
    uint32_t cp = index / k;
    uint8_t v[32];
    memcpy(v, checkpoints + (size_t)cp * len, len);
    for (uint32_t i = cp * k; i < index; i++)
        chainStep(v, len, v);
    memcpy(out, v, len);
    return true;
}

// ---------------------------------------------------------------- HMAC / TOTP

void hmacToken(const uint8_t *key, size_t keyLen, uint32_t beaconId, uint32_t epochId, uint32_t counter, uint32_t outLen,
               uint8_t *out)
{
    uint8_t msg[16] = {'H', 'M', 'P', 'H'};
    putU32(msg + 4, beaconId);
    putU32(msg + 8, epochId);
    putU32(msg + 12, counter);
    uint8_t mac[32];
    hmacSha256(key, keyLen, msg, sizeof(msg), mac);
    memcpy(out, mac, outLen);
}

uint32_t totpCode(const uint8_t *key, size_t keyLen, uint64_t t, uint32_t digits)
{
    uint8_t msg[8];
    putU64(msg, t);
    uint8_t mac[32];
    hmacSha256(key, keyLen, msg, 8, mac);
    uint8_t off = mac[31] & 0x0F;
    uint32_t bin =
        ((uint32_t)(mac[off] & 0x7F) << 24) | ((uint32_t)mac[off + 1] << 16) | ((uint32_t)mac[off + 2] << 8) | mac[off + 3];
    uint32_t mod = 1;
    for (uint32_t i = 0; i < digits; i++)
        mod *= 10;
    return bin % mod;
}

// ---------------------------------------------------------------- admin plane

bool parseAdminCommand(const uint8_t *buf, size_t len, AdminCommand &out)
{
    if (len < CMD_HEADER_LEN)
        return false;
    out.version = buf[0];
    out.command = buf[1];
    out.target = getU32(buf + 2);
    out.counter = getU64(buf + 6);
    if (out.version == CMD_VERSION_SIGNED) {
        if (len < CMD_HEADER_LEN + SIG_LEN)
            return false;
        out.body = buf + CMD_HEADER_LEN;
        out.bodyLen = len - CMD_HEADER_LEN - SIG_LEN;
        out.signature = buf + len - SIG_LEN;
        return true;
    }
    if (out.version == CMD_VERSION_LOCAL) {
        out.body = buf + CMD_HEADER_LEN;
        out.bodyLen = len - CMD_HEADER_LEN;
        out.signature = nullptr;
        return true;
    }
    return false;
}

static bool verifyWithPrefix(const char *prefix, const uint8_t *buf, size_t len, const uint8_t pub[32])
{
    if (len < SIG_LEN || len > 512)
        return false;
    uint8_t msg[5 + 512];
    memcpy(msg, prefix, 5);
    memcpy(msg + 5, buf, len - SIG_LEN);
    return ed25519Verify(buf + len - SIG_LEN, pub, msg, 5 + len - SIG_LEN);
}

static size_t signWithPrefix(const char *prefix, uint8_t *buf, size_t unsignedLen, size_t cap, const uint8_t priv[32],
                             const uint8_t pub[32])
{
    if (unsignedLen + SIG_LEN > cap || unsignedLen > 512 - SIG_LEN)
        return 0;
    uint8_t msg[5 + 512];
    memcpy(msg, prefix, 5);
    memcpy(msg + 5, buf, unsignedLen);
    ed25519Sign(buf + unsignedLen, priv, pub, msg, 5 + unsignedLen);
    return unsignedLen + SIG_LEN;
}

bool verifyAdminCommand(const uint8_t *buf, size_t len, const uint8_t adminPub[32])
{
    return len >= CMD_HEADER_LEN + SIG_LEN && buf[0] == CMD_VERSION_SIGNED && verifyWithPrefix("HMPA1", buf, len, adminPub);
}

size_t buildAdminCommand(uint8_t *out, size_t cap, uint8_t command, uint32_t target, uint64_t counter, const uint8_t *body,
                         size_t bodyLen, const uint8_t priv[32], const uint8_t pub[32])
{
    if (CMD_HEADER_LEN + bodyLen + SIG_LEN > cap)
        return 0;
    out[0] = CMD_VERSION_SIGNED;
    out[1] = command;
    putU32(out + 2, target);
    putU64(out + 6, counter);
    if (bodyLen)
        memcpy(out + CMD_HEADER_LEN, body, bodyLen);
    return signWithPrefix("HMPA1", out, CMD_HEADER_LEN + bodyLen, cap, priv, pub);
}

size_t buildReply(uint8_t *out, size_t cap, uint8_t code, uint32_t beaconId, uint64_t counter, uint8_t status,
                  const uint8_t *body, size_t bodyLen, const uint8_t priv[32], const uint8_t pub[32])
{
    if (REPLY_HEADER_LEN + bodyLen + SIG_LEN > cap)
        return 0;
    out[0] = 0x01;
    out[1] = code;
    putU32(out + 2, beaconId);
    putU64(out + 6, counter);
    out[14] = status;
    if (bodyLen)
        memcpy(out + REPLY_HEADER_LEN, body, bodyLen);
    return signWithPrefix("HMPR1", out, REPLY_HEADER_LEN + bodyLen, cap, priv, pub);
}

bool verifyReply(const uint8_t *buf, size_t len, const uint8_t beaconPub[32])
{
    return len >= REPLY_HEADER_LEN + SIG_LEN && verifyWithPrefix("HMPR1", buf, len, beaconPub);
}

bool parseEpochBody(const uint8_t *b, size_t len, EpochBody &out)
{
    if (len < EPOCH_BODY_FIXED_LEN)
        return false;
    out.nowUnix = getU64(b);
    out.epochId = getU32(b + 8);
    out.epochStartUnix = getU64(b + 12);
    out.chainTickBase = getU32(b + 20);
    out.hmacCounterBase = getU32(b + 24);
    out.totpT0 = getU64(b + 28);
    out.tlv = b + EPOCH_BODY_FIXED_LEN;
    out.tlvLen = len - EPOCH_BODY_FIXED_LEN;
    return true;
}

double distanceMeters(int32_t lat1, int32_t lon1, int32_t lat2, int32_t lon2)
{
    const double r = 6371000.0, d = M_PI / 180.0 / 1e7;
    double p1 = lat1 * d, p2 = lat2 * d, dp = (lat2 - lat1) * d, dl = ((double)lon2 - lon1) * d;
    double a = sin(dp / 2) * sin(dp / 2) + cos(p1) * cos(p2) * sin(dl / 2) * sin(dl / 2);
    return 2 * r * atan2(sqrt(a), sqrt(1 - a));
}

} // namespace hmp
#endif
