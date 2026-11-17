#pragma once
// Hot Mess presence beacon: portable core (no Arduino or Meshtastic headers), so the same code
// builds into the firmware and into the host test that produces the verifier's test vectors.
#include <cstddef>
#include <cstdint>

namespace hmp
{

// ---- Crypto hooks: PresenceCryptoDevice.cpp on the beacon, the host test links its own ----
struct Sha256Ctx {
    alignas(8) uint8_t opaque[160];
};
void sha256Begin(Sha256Ctx &ctx);
void sha256Update(Sha256Ctx &ctx, const void *data, size_t len);
void sha256Final(Sha256Ctx &ctx, uint8_t out[32]);
bool ed25519Verify(const uint8_t sig[64], const uint8_t pub[32], const uint8_t *msg, size_t len);
void ed25519Sign(uint8_t sig[64], const uint8_t priv[32], const uint8_t pub[32], const uint8_t *msg, size_t len);
void ed25519DerivePublic(uint8_t pub[32], const uint8_t priv[32]);

void sha256(const void *data, size_t len, uint8_t out[32]);
void hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *msg, size_t msgLen, uint8_t out[32]);

// ---- Big-endian helpers ----
inline void putU16(uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}
inline void putU32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}
inline void putU64(uint8_t *p, uint64_t v)
{
    putU32(p, (uint32_t)(v >> 32));
    putU32(p + 4, (uint32_t)v);
}
inline uint16_t getU16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}
inline uint32_t getU32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
inline uint64_t getU64(const uint8_t *p)
{
    return ((uint64_t)getU32(p) << 32) | getU32(p + 4);
}

// ---- Runtime parameters. Every timing and size value lives here; nothing is fixed in code. ----
// Wire ids for the TLV encoding used by RESYNC / ROTATE_CHAIN. Values are big-endian; ids 29-31
// carry raw bytes. Unknown ids are rejected so a typo cannot silently do nothing.
enum ParamId : uint8_t {
    P_TICK_MS = 1,
    P_CHAIN_LENGTH = 2,
    P_CHAIN_VALUE_LEN = 3,
    P_CHECKPOINT_INTERVAL = 4,
    P_HMAC_LEN = 5,
    P_TOTP_STEP_S = 6,
    P_TOTP_DIGITS = 7,
    P_SCHEME_MASK = 8,
    P_WEIGHT_PRESENCE = 9,
    P_WEIGHT_IBEACON = 10,
    P_WEIGHT_EDDYSTONE = 11,
    P_STATUS_EVERY = 12,
    P_SLOT_MS = 13,
    P_ADV_INTERVAL_MS = 14,
    P_ADDRESS_ROTATE_SLOTS = 15,
    P_THEFT_RADIUS_M = 16,
    P_THEFT_CHECK_S = 17,
    P_THEFT_REPORT_S = 18,
    P_THEFT_CONFIRM_FIXES = 19,
    P_PERSIST_EVERY_TICKS = 20,
    P_WINDOW_BACK_TICKS = 21,
    P_WINDOW_FWD_TICKS = 22,
    P_FW_HASH_LEN = 23,
    P_KEY_FP_LEN = 24,
    P_COMPANY_ID = 25,
    P_TX_POWER_DBM = 26,
    P_IBEACON_MAJOR = 27,
    P_IBEACON_MINOR = 28,
    P_IBEACON_UUID = 29,
    P_EDDYSTONE_NAMESPACE = 30,
    P_EDDYSTONE_INSTANCE = 31,
    P_TOTP_WINDOW_STEPS = 32,
    P_CHAIN_GEN_BATCH = 33,
    P_CHECKPOINT_RAM_MAX = 34,
    P_BOOT_REPORT_DELAY_S = 35,
    P_MAX_ID = 35
};

enum SchemeBit : uint8_t { SCHEME_CHAIN = 1, SCHEME_HMAC = 2, SCHEME_TOTP = 4 };

struct Params {
    uint32_t tickMs;
    uint32_t chainLength;
    uint32_t chainValueLen;
    uint32_t checkpointInterval;
    uint32_t hmacLen;
    uint32_t totpStepS;
    uint32_t totpDigits;
    uint32_t schemeMask;
    uint32_t weightPresence;
    uint32_t weightIBeacon;
    uint32_t weightEddystone;
    uint32_t statusEvery;
    uint32_t slotMs;
    uint32_t advIntervalMs;
    uint32_t addressRotateSlots;
    uint32_t theftRadiusM;
    uint32_t theftCheckS;
    uint32_t theftReportS;
    uint32_t theftConfirmFixes;
    uint32_t persistEveryTicks;
    uint32_t windowBackTicks;
    uint32_t windowFwdTicks;
    uint32_t fwHashLen;
    uint32_t keyFpLen;
    uint32_t companyId;
    int32_t txPowerDbm;
    uint32_t iBeaconMajor;
    uint32_t iBeaconMinor;
    uint8_t iBeaconUuid[16];
    uint8_t eddystoneNamespace[10];
    uint8_t eddystoneInstance[6];
    uint32_t totpWindowSteps;
    uint32_t chainGenBatch;
    uint32_t checkpointRamMax;
    uint32_t bootReportDelayS;
};

void defaultParams(Params &p);
// Applies a TLV list on top of `p`. Returns false (and leaves `p` untouched) on a malformed or
// unknown entry, or if the result fails validate().
bool applyParamTlv(Params &p, const uint8_t *tlv, size_t len);
size_t encodeParamTlv(const Params &p, uint8_t *out, size_t cap); // every id, for tests and docs
bool validateParams(const Params &p);

// ---- Frame layout (manufacturer data after the 2-byte company id) ----
// [0] (FRAME_VERSION << 4) | kind  [1..4] beacon id  [5..6] epoch id low 16  [7..10] tick / counter / T
// [11..] token. The phone concatenates the advertisement's and the scan response's manufacturer data.
static const uint8_t FRAME_VERSION = 1;
enum FrameKind : uint8_t { KIND_STATUS = 0x0, KIND_CHAIN = 0x1, KIND_HMAC = 0x2, KIND_TOTP = 0x3 };
static const size_t FRAME_HEADER_LEN = 11;
static const size_t ADV_MFR_PAYLOAD_MAX = 24;      // 31 - flags(3) - AD header(2) - company id(2)
static const size_t SCANRSP_MFR_PAYLOAD_MAX = 27;  // 31 - AD header(2) - company id(2)
static const size_t FRAME_MAX = ADV_MFR_PAYLOAD_MAX + SCANRSP_MFR_PAYLOAD_MAX;

size_t encodePresenceFrame(uint8_t *out, uint8_t kind, uint32_t beaconId, uint32_t epochId, uint32_t position,
                           const uint8_t *token, size_t tokenLen);
// Status frame: header (position = 0) + fw major, minor, build + fw hash prefix + admin key fingerprint.
// No moved/theft flag: a moved beacon must look exactly like one in place.
size_t encodeStatusFrame(uint8_t *out, uint32_t beaconId, uint32_t epochId, const uint8_t fwVersion[3], const uint8_t *fwHash,
                         size_t fwHashLen, const uint8_t *keyFp, size_t keyFpLen);

// ---- Presence schemes ----
// Hash chain: x0 = Trunc_L(SHA256("HMPC-seed" || seed)), x(i+1) = Trunc_L(SHA256("HMPC" || x(i))),
// anchor = x(N). At chain tick t (1..N) the beacon reveals x(N - t).
void chainSeedToX0(const uint8_t seed[32], uint32_t valueLen, uint8_t *out);
void chainStep(const uint8_t *in, uint32_t valueLen, uint8_t *out);

class HashChain
{
  public:
    HashChain() {}
    ~HashChain();
    // Starts (re)generation from a seed. The caller then pumps generate() until it returns true.
    bool begin(const uint8_t seed[32], uint32_t chainLength, uint32_t valueLen, uint32_t checkpointInterval,
               uint32_t ramMax);
    bool generate(uint32_t maxSteps); // true once complete
    bool ready() const { return state == READY; }
    bool generating() const { return state == GENERATING; }
    const uint8_t *anchor() const { return anchorValue; }
    uint32_t length() const { return n; }
    // Value revealed at chain tick t (1..N). False when not ready or t out of range.
    bool valueAtTick(uint32_t t, uint8_t *out) const;
    void clear();

  private:
    enum { EMPTY, GENERATING, READY } state = EMPTY;
    uint8_t *checkpoints = nullptr; // x(0), x(K), x(2K), ...
    uint32_t n = 0, len = 0, k = 0, nextIndex = 0;
    uint8_t cursor[32] = {0};
    uint8_t anchorValue[32] = {0};
};

// HMAC counter: Trunc_Lh(HMAC-SHA256(K, "HMPH" || beacon id || epoch id || counter)), all u32 BE.
void hmacToken(const uint8_t *key, size_t keyLen, uint32_t beaconId, uint32_t epochId, uint32_t counter, uint32_t outLen,
               uint8_t *out);
// TOTP: RFC 6238 with HMAC-SHA256 over T as u64 BE, dynamic truncation, `digits` decimal digits.
uint32_t totpCode(const uint8_t *key, size_t keyLen, uint64_t t, uint32_t digits);

// ---- Admin plane (LoRa, signed) ----
// Command: [0] version (0x01 signed, 0x81 unsigned, accepted only from the local USB client)
// [1] command [2..5] target node [6..13] command counter, u64 [14..] body [last 64] Ed25519
// signature over "HMPA1" || everything before it.
static const uint8_t CMD_VERSION_SIGNED = 0x01;
static const uint8_t CMD_VERSION_LOCAL = 0x81;
static const size_t CMD_HEADER_LEN = 14;
static const size_t SIG_LEN = 64;
enum Command : uint8_t {
    CMD_TIME_SYNC = 0x01,
    CMD_RESYNC = 0x02,
    CMD_ROTATE_CHAIN = 0x03,
    CMD_SET_HOME = 0x04,
    CMD_STATUS = 0x05,
    CMD_SET_FRAMES = 0x06,
    CMD_DECOMMISSION = 0x07,
    CMD_ROTATE_ADMIN_KEY = 0x08,
    CMD_PROVISION = 0x10, // local only
    // Unsolicited reports from the beacon
    REPORT_MOVED = 0xA0,
    REPORT_BOOT = 0xA1
};
enum ReplyStatus : uint8_t {
    ST_OK = 0,
    ST_BAD_SIGNATURE = 1,
    ST_REPLAY = 2,
    ST_BAD_TARGET = 3,
    ST_BAD_BODY = 4,
    ST_NOT_PROVISIONED = 5,
    ST_REJECTED = 6,
    ST_BUSY = 7,
    ST_UNKNOWN_COMMAND = 8,
    ST_PENDING = 9
};

struct AdminCommand {
    uint8_t version;
    uint8_t command;
    uint32_t target;
    uint64_t counter;
    const uint8_t *body;
    size_t bodyLen;
    const uint8_t *signature; // null for local unsigned commands
};
bool parseAdminCommand(const uint8_t *buf, size_t len, AdminCommand &out);
bool verifyAdminCommand(const uint8_t *buf, size_t len, const uint8_t adminPub[32]);
// Builds a signed command (server side; used by the host test and mirrored by the Ruby verifier).
size_t buildAdminCommand(uint8_t *out, size_t cap, uint8_t command, uint32_t target, uint64_t counter, const uint8_t *body,
                         size_t bodyLen, const uint8_t priv[32], const uint8_t pub[32]);

// Reply: [0] 0x01 [1] command | 0x80 (unsolicited reports use 0xA0+) [2..5] beacon node [6..13] echoed
// counter [14] status [15..] body [last 64] beacon Ed25519 signature over "HMPR1" || everything before it.
static const size_t REPLY_HEADER_LEN = 15;
size_t buildReply(uint8_t *out, size_t cap, uint8_t code, uint32_t beaconId, uint64_t counter, uint8_t status,
                  const uint8_t *body, size_t bodyLen, const uint8_t priv[32], const uint8_t pub[32]);
bool verifyReply(const uint8_t *buf, size_t len, const uint8_t beaconPub[32]);

// Epoch body shared by RESYNC and ROTATE_CHAIN:
// now_unix u64 | epoch_id u32 | epoch_start_unix u64 | chain_tick_base u32 | hmac_counter_base u32 |
// totp_t0 u64 | param TLV...
static const size_t EPOCH_BODY_FIXED_LEN = 36;
struct EpochBody {
    uint64_t nowUnix;
    uint32_t epochId;
    uint64_t epochStartUnix;
    uint32_t chainTickBase;
    uint32_t hmacCounterBase;
    uint64_t totpT0;
    const uint8_t *tlv;
    size_t tlvLen;
};
bool parseEpochBody(const uint8_t *body, size_t len, EpochBody &out);

// Great-circle distance in metres between two points in 1e-7 degrees.
double distanceMeters(int32_t lat1, int32_t lon1, int32_t lat2, int32_t lon2);

} // namespace hmp
