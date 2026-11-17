// Self-checks for the presence core, then prints vectors.json for the AudienceKit verifier.
#include "../../src/modules/optional/HotMessPresence/PresenceCore.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace hmp;

static int failures = 0;
#define CHECK(c)                                                                                                                 \
    do {                                                                                                                         \
        if (!(c)) {                                                                                                              \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c);                                                          \
            failures++;                                                                                                          \
        }                                                                                                                        \
    } while (0)

static std::string hex(const uint8_t *b, size_t n)
{
    static const char *d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) {
        s += d[b[i] >> 4];
        s += d[b[i] & 15];
    }
    return s;
}

// Naive reference: x(N - t) by walking the whole chain.
static void naiveValue(const uint8_t seed[32], uint32_t n, uint32_t len, uint32_t t, uint8_t *out)
{
    uint8_t v[32];
    chainSeedToX0(seed, len, v);
    for (uint32_t i = 0; i < n - t; i++)
        chainStep(v, len, v);
    memcpy(out, v, len);
}

static void chainCase(const char *name, uint32_t n, uint32_t len, uint32_t k, const uint32_t *ticks, size_t nt, bool last)
{
    uint8_t seed[32];
    for (int i = 0; i < 32; i++)
        seed[i] = (uint8_t)i;
    HashChain c;
    CHECK(c.begin(seed, n, len, k, 1 << 20));
    while (!c.generate(7)) {
    }
    uint8_t anchor[32];
    naiveValue(seed, n, len, 0, anchor);
    CHECK(memcmp(anchor, c.anchor(), len) == 0);
    printf("    {\"name\": \"%s\", \"seed\": \"%s\", \"length\": %u, \"value_len\": %u, \"checkpoint_interval\": %u, \"anchor\": "
           "\"%s\", \"reveals\": [",
           name, hex(seed, 32).c_str(), n, len, k, hex(c.anchor(), len).c_str());
    for (size_t i = 0; i < nt; i++) {
        uint8_t v[32], ref[32];
        CHECK(c.valueAtTick(ticks[i], v));
        naiveValue(seed, n, len, ticks[i], ref);
        CHECK(memcmp(v, ref, len) == 0);
        printf("%s{\"tick\": %u, \"value\": \"%s\"}", i ? ", " : "", ticks[i], hex(v, len).c_str());
    }
    uint8_t dummy[32];
    CHECK(!c.valueAtTick(0, dummy) && !c.valueAtTick(n + 1, dummy));
    printf("]}%s\n", last ? "" : ",");
}

int main()
{
    printf("{\n  \"generated_by\": \"test/hotmess_presence_host (PresenceCore.cpp)\",\n");

    // ---- params
    Params p;
    defaultParams(p);
    CHECK(validateParams(p));
    uint8_t tlv[512];
    size_t tl = encodeParamTlv(p, tlv, sizeof(tlv));
    CHECK(tl > 0);
    Params q;
    defaultParams(q);
    q.tickMs = 1;
    CHECK(!applyParamTlv(q, (const uint8_t *)"\x01\x02\x00\x01", 4)); // tick 1 ms fails validation
    CHECK(applyParamTlv(q, tlv, tl) && memcmp(&p, &q, sizeof(p)) == 0);
    CHECK(!applyParamTlv(q, (const uint8_t *)"\x63\x01\x00", 3)); // unknown id
    const uint8_t neg[] = {P_TX_POWER_DBM, 1, 0xF8};              // -8 dBm in one byte
    CHECK(applyParamTlv(q, neg, sizeof(neg)) && q.txPowerDbm == -8);
    printf("  \"default_params_tlv\": \"%s\",\n", hex(tlv, tl).c_str());

    // ---- hash chain
    printf("  \"chains\": [\n");
    const uint32_t t1[] = {1, 2, 5, 8, 9, 31, 63, 64};
    chainCase("short-16", 64, 16, 8, t1, 8, false);
    const uint32_t t2[] = {1, 3, 4, 19, 20};
    chainCase("odd-32", 20, 32, 3, t2, 5, true);
    printf("  ],\n");

    // ---- HMAC counter
    uint8_t key[32];
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)(i + 1);
    printf("  \"hmac\": {\"key\": \"%s\", \"beacon_id\": %u, \"epoch_id\": 7, \"len\": 8, \"tokens\": [", hex(key, 32).c_str(),
           0x0A0B0C0Du);
    const uint32_t counters[] = {1, 2, 1000, 0xFFFFFFFF};
    for (int i = 0; i < 4; i++) {
        uint8_t t[32];
        hmacToken(key, 32, 0x0A0B0C0D, 7, counters[i], 8, t);
        printf("%s{\"counter\": %u, \"token\": \"%s\"}", i ? ", " : "", counters[i], hex(t, 8).c_str());
    }
    printf("]},\n");

    // ---- TOTP: RFC 6238 appendix B, SHA-256 column
    const uint8_t rfcKey[] = "12345678901234567890123456789012";
    const uint64_t times[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000ULL};
    const uint32_t expect[] = {46119246, 68084774, 67062674, 91819424, 90698825, 77737706};
    printf("  \"totp\": {\"key\": \"%s\", \"step\": 30, \"t0\": 0, \"digits\": 8, \"codes\": [", hex(rfcKey, 32).c_str());
    for (int i = 0; i < 6; i++) {
        uint32_t c = totpCode(rfcKey, 32, times[i] / 30, 8);
        CHECK(c == expect[i]);
        printf("%s{\"unix\": %llu, \"code\": %u}", i ? ", " : "", (unsigned long long)times[i], c);
    }
    printf("]},\n");

    // ---- frames
    uint8_t frame[FRAME_MAX], tok[16];
    memset(tok, 0xAB, 16);
    size_t fl = encodePresenceFrame(frame, KIND_CHAIN, 0x0A0B0C0D, 0x12345, 42, tok, 16);
    CHECK(fl == 27);
    printf("  \"frames\": {\"chain\": \"%s\", ", hex(frame, fl).c_str());
    const uint8_t fw[3] = {2, 8, 3};
    uint8_t fh[32], fp[32];
    memset(fh, 0x11, 32);
    memset(fp, 0x22, 32);
    fl = encodeStatusFrame(frame, 0x0A0B0C0D, 3, fw, fh, 8, fp, 4);
    CHECK(fl == 26 && (frame[0] & 0x0F) == KIND_STATUS);
    printf("\"status\": \"%s\"},\n", hex(frame, fl).c_str());

    // ---- admin plane
    uint8_t adminPriv[32], adminPub[32], beaconPriv[32], beaconPub[32];
    memset(adminPriv, 0x42, 32);
    memset(beaconPriv, 0x24, 32);
    ed25519DerivePublic(adminPub, adminPriv);
    ed25519DerivePublic(beaconPub, beaconPriv);
    uint8_t cmd[256];
    size_t cl = buildAdminCommand(cmd, sizeof(cmd), CMD_STATUS, 0x0A0B0C0D, 5, nullptr, 0, adminPriv, adminPub);
    CHECK(cl == CMD_HEADER_LEN + SIG_LEN && verifyAdminCommand(cmd, cl, adminPub));
    AdminCommand ac;
    CHECK(parseAdminCommand(cmd, cl, ac) && ac.command == CMD_STATUS && ac.counter == 5 && ac.target == 0x0A0B0C0D);
    cmd[3] ^= 1;
    CHECK(!verifyAdminCommand(cmd, cl, adminPub));
    cmd[3] ^= 1;
    printf("  \"admin\": {\"admin_private\": \"%s\", \"admin_public\": \"%s\", \"beacon_private\": \"%s\", \"beacon_public\": "
           "\"%s\",\n",
           hex(adminPriv, 32).c_str(), hex(adminPub, 32).c_str(), hex(beaconPriv, 32).c_str(), hex(beaconPub, 32).c_str());
    printf("    \"status_command\": \"%s\",\n", hex(cmd, cl).c_str());

    uint8_t body[64];
    putU64(body, 1800000000);
    putU32(body + 8, 2);
    putU64(body + 12, 1800000000);
    putU32(body + 20, 1);
    putU32(body + 24, 1);
    putU64(body + 28, 0);
    body[36] = P_TICK_MS;
    body[37] = 2;
    putU16(body + 38, 15000);
    cl = buildAdminCommand(cmd, sizeof(cmd), CMD_RESYNC, 0x0A0B0C0D, 6, body, 40, adminPriv, adminPub);
    EpochBody eb;
    CHECK(parseAdminCommand(cmd, cl, ac) && parseEpochBody(ac.body, ac.bodyLen, eb) && eb.epochId == 2 && eb.tlvLen == 4);
    Params r;
    defaultParams(r);
    CHECK(applyParamTlv(r, eb.tlv, eb.tlvLen) && r.tickMs == 15000);
    printf("    \"resync_command\": \"%s\",\n", hex(cmd, cl).c_str());

    uint8_t rb[12];
    putU32(rb, 2);
    putU32(rb + 4, 1);
    putU32(rb + 8, 1);
    uint8_t rep[256];
    size_t rl = buildReply(rep, sizeof(rep), CMD_RESYNC | 0x80, 0x0A0B0C0D, 6, ST_OK, rb, 12, beaconPriv, beaconPub);
    CHECK(verifyReply(rep, rl, beaconPub));
    printf("    \"resync_reply\": \"%s\"\n  },\n", hex(rep, rl).c_str());

    // ---- distance sanity: ~111 m per 0.001 deg latitude
    double d = distanceMeters(468721000, -1139940000, 468731000, -1139940000);
    CHECK(d > 110 && d < 112);
    printf("  \"failures\": %d\n}\n", failures);
    return failures ? 1 : 0;
}
