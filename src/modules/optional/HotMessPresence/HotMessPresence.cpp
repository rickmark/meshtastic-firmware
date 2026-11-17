// Hot Mess Bluetooth presence beacon (pilot). Owns the nRF52's Bluetooth advertising, runs the hash
// chain, HMAC-counter and TOTP presence schemes side by side, and takes signed write-only admin
// commands over LoRa. Nothing here senses, stores or reports anything about people.
#include "configuration.h"

#include "HotMessPresence.h"

#if defined(ARCH_NRF52) && !defined(ARCH_NRF54L)
#include "FSCommon.h"
#include "GPSStatus.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "PowerStatus.h"
#include "PresenceAdvertiser.h"
#include "PresenceCore.h"
#include "SPILock.h"
#include "SafeFile.h"
#include "SinglePortModule.h"
#include "concurrency/OSThread.h"
#include "main.h"
#include "HardwareRNG.h"
#include <cstddef>
#include <cstdio>
#include <cstring>

#ifndef HOTMESS_PRESENCE_PORTNUM
#define HOTMESS_PRESENCE_PORTNUM 287 // inside the private-app range 256-511
#endif

extern "C" {
extern uint32_t __flash_arduino_start;
extern uint32_t __etext;
extern uint32_t __data_start__;
extern uint32_t __data_end__;
}
class NRF52Bluetooth;
extern NRF52Bluetooth *nrf52Bluetooth;

using namespace hmp;

namespace
{

const char *STATE_FILE = "/prefs/hmpresence.bin";
const uint32_t STATE_MAGIC = 0x484D5053; // "HMPS"
const uint32_t STATE_VERSION = 1;

enum FrameBit : uint8_t { FRAME_PRESENCE = 1, FRAME_STATUS = 2, FRAME_IBEACON = 4, FRAME_EDDYSTONE = 8 };

struct PilotCounts {
    uint32_t presenceFrames, statusFrames, iBeaconFrames, eddystoneFrames, adminAccepted, adminRejected;
};

// Everything the beacon keeps across reboots. Per-beacon data only: no phone addresses, no people.
struct PersistedState {
    uint32_t magic, version;
    Params params;
    uint8_t provisioned, beaconMode, frameMask, homeSet, moved, adminPki, adminChannel, epochSet;
    uint8_t devicePriv[32], devicePub[32], adminPub[32];
    uint8_t hmacKey[32], totpKey[32];
    uint8_t hmacKeyLen, totpKeyLen, seedSet, pad;
    uint8_t seed[32];
    uint64_t lastAdminCounter;
    uint32_t epochId;
    uint64_t epochStartUnix;
    uint32_t chainTickBase, hmacCounterBase;
    uint64_t totpT0;
    uint32_t reservedTick;
    int32_t homeLat, homeLon;
    uint32_t reportTo;
    PilotCounts counts;
    uint8_t check[32];
};

struct PendingRotate {
    bool active;
    uint64_t counter;
    NodeNum to;
    uint8_t channel;
    bool pki;
};

} // namespace

class HotMessPresenceModule : public SinglePortModule, private concurrency::OSThread
{
  public:
    HotMessPresenceModule()
        : SinglePortModule("hotmess-presence", (meshtastic_PortNum)HOTMESS_PRESENCE_PORTNUM), concurrency::OSThread("HotMessPresence")
    {
        computeFirmwareIdentity();
        if (!load())
            resetState();
        if (st.seedSet)
            chain.begin(st.seed, st.params.chainLength, st.params.chainValueLen, st.params.checkpointInterval,
                        st.params.checkpointRamMax);
        resumeTick = st.reservedTick;
        lastMillis = millis();
        LOG_INFO("HotMess presence: provisioned=%d beaconMode=%d epoch=%u", st.provisioned, st.beaconMode, st.epochId);
    }

  protected:
    ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;
    int32_t runOnce() override;

  private:
    PersistedState st;
    HashChain chain;
    PresenceAdvertiser adv;
    PendingRotate pendingRotate = {};

    uint8_t fwVersion[3] = {0};
    uint8_t fwHash[32] = {0};

    // Monotonic clock (ms since boot, 64-bit) and the wall-clock offset from the last signed sync.
    uint64_t monoMs = 0;
    uint32_t lastMillis = 0;
    bool clockValid = false;
    uint64_t unixMsAtSync = 0, monoAtSync = 0;
    uint32_t resumeTick = 0, lastTick = 0;

    // Scheduler
    int32_t wrr[3] = {0, 0, 0};
    uint32_t presenceSlots = 0, schemeCursor = 0;
    uint8_t randomAddr[6] = {0};
    uint64_t lastTheftCheckMs = 0, lastMovedReportMs = 0;
    uint32_t outsideFixes = 0;
    bool bootReported = false;
    bool decommissionPending = false;

    // ------------------------------------------------------------ persistence
    void resetState()
    {
        memset(&st, 0, sizeof(st));
        st.magic = STATE_MAGIC;
        st.version = STATE_VERSION;
        defaultParams(st.params);
        st.frameMask = FRAME_PRESENCE | FRAME_STATUS | FRAME_IBEACON | FRAME_EDDYSTONE;
    }

    bool load()
    {
        concurrency::LockGuard g(spiLock);
        auto f = FSCom.open(STATE_FILE, FILE_O_READ);
        if (!f)
            return false;
        bool ok = f.read(reinterpret_cast<uint8_t *>(&st), sizeof(st)) == sizeof(st);
        f.close();
        uint8_t h[32];
        sha256(&st, offsetof(PersistedState, check), h);
        if (!ok || st.magic != STATE_MAGIC || st.version != STATE_VERSION || memcmp(h, st.check, 32) != 0 ||
            !validateParams(st.params)) {
            LOG_WARN("HotMess presence: state file invalid, starting unprovisioned");
            return false;
        }
        return true;
    }

    void save()
    {
        sha256(&st, offsetof(PersistedState, check), st.check);
        SafeFile f(STATE_FILE, true);
        f.write(reinterpret_cast<const uint8_t *>(&st), sizeof(st));
        if (!f.close())
            LOG_ERROR("HotMess presence: state save failed");
    }

    void wipe()
    {
        {
            concurrency::LockGuard g(spiLock);
            if (FSCom.exists(STATE_FILE))
                FSCom.remove(STATE_FILE);
        }
        chain.clear();
        memset(&st, 0, sizeof(st)); // drop keys and seed from RAM too
        resetState();
        adv.stop();
        clockValid = false;
    }

    // ------------------------------------------------------------ identity
    void computeFirmwareIdentity()
    {
        unsigned a = 0, b = 0, c = 0;
        sscanf(APP_VERSION_SHORT, "%u.%u.%u", &a, &b, &c);
        fwVersion[0] = (uint8_t)a;
        fwVersion[1] = (uint8_t)b;
        fwVersion[2] = (uint8_t)c;
        // SHA-256 over the image exactly as firmware.bin lays it out: code from the start of the
        // application region to __etext, followed by the initialised-data load image.
        const uint8_t *start = reinterpret_cast<const uint8_t *>(&__flash_arduino_start);
        const uint8_t *etext = reinterpret_cast<const uint8_t *>(&__etext);
        size_t dataLen = reinterpret_cast<const uint8_t *>(&__data_end__) - reinterpret_cast<const uint8_t *>(&__data_start__);
        Sha256Ctx ctx;
        sha256Begin(ctx);
        sha256Update(ctx, start, etext - start);
        sha256Update(ctx, etext, dataLen);
        sha256Final(ctx, fwHash);
    }

    void adminKeyFingerprint(uint8_t out[32]) { sha256(st.adminPub, 32, out); }

    void deriveStaticAddr(const char *label, uint8_t out[6])
    {
        uint8_t h[32];
        Sha256Ctx ctx;
        sha256Begin(ctx);
        sha256Update(ctx, label, strlen(label));
        sha256Update(ctx, st.devicePub, 32);
        sha256Final(ctx, h);
        memcpy(out, h, 6);
        out[0] |= 0xC0; // random static address
    }

    // ------------------------------------------------------------ clock and epoch
    void updateMono()
    {
        uint32_t now = millis();
        monoMs += (uint32_t)(now - lastMillis);
        lastMillis = now;
    }

    void setClock(uint64_t unixSeconds)
    {
        unixMsAtSync = unixSeconds * 1000ULL;
        monoAtSync = monoMs;
        clockValid = true;
    }

    uint64_t nowUnixMs() const { return unixMsAtSync + (monoMs - monoAtSync); }

    // Chain tick for "now". Never moves backwards within an epoch.
    uint32_t currentTick()
    {
        if (!st.epochSet)
            return 0;
        uint64_t t;
        if (clockValid) {
            uint64_t start = st.epochStartUnix * 1000ULL, now = nowUnixMs();
            t = now < start ? st.chainTickBase : st.chainTickBase + (now - start) / st.params.tickMs;
        } else {
            // No trusted time since boot: carry on from the persisted reservation.
            t = (uint64_t)resumeTick + monoMs / st.params.tickMs;
        }
        if (t > 0xFFFFFFFFULL)
            t = 0xFFFFFFFFULL;
        if (t < lastTick)
            t = lastTick;
        lastTick = (uint32_t)t;
        if (lastTick >= st.reservedTick) {
            st.reservedTick = lastTick + st.params.persistEveryTicks;
            save();
        }
        return lastTick;
    }

    uint32_t currentCounter(uint32_t tick) const { return st.hmacCounterBase + (tick - st.chainTickBase); }

    // ------------------------------------------------------------ frames
    bool buildPresence(uint8_t *frame, size_t &len)
    {
        uint32_t tick = currentTick();
        uint32_t me = nodeDB->getNodeNum();
        for (int tries = 0; tries < 3; tries++) {
            uint8_t bit = 1 << (schemeCursor++ % 3);
            if (!(st.params.schemeMask & bit))
                continue;
            uint8_t tok[32];
            if (bit == SCHEME_CHAIN && chain.ready() && chain.valueAtTick(tick, tok)) {
                len = encodePresenceFrame(frame, KIND_CHAIN, me, st.epochId, tick, tok, st.params.chainValueLen);
                return len > 0;
            }
            if (bit == SCHEME_HMAC && st.hmacKeyLen) {
                uint32_t counter = currentCounter(tick);
                hmacToken(st.hmacKey, st.hmacKeyLen, me, st.epochId, counter, st.params.hmacLen, tok);
                len = encodePresenceFrame(frame, KIND_HMAC, me, st.epochId, counter, tok, st.params.hmacLen);
                return len > 0;
            }
            if (bit == SCHEME_TOTP && st.totpKeyLen && clockValid) {
                uint64_t now = nowUnixMs() / 1000;
                if (now < st.totpT0)
                    continue;
                uint64_t t = (now - st.totpT0) / st.params.totpStepS;
                putU32(tok, totpCode(st.totpKey, st.totpKeyLen, t, st.params.totpDigits));
                len = encodePresenceFrame(frame, KIND_TOTP, me, st.epochId, (uint32_t)t, tok, 4);
                return len > 0;
            }
        }
        return false;
    }

    size_t buildStatus(uint8_t *frame)
    {
        uint8_t fp[32];
        adminKeyFingerprint(fp);
        return encodeStatusFrame(frame, nodeDB->getNodeNum(), st.epochId, fwVersion, fwHash, st.params.fwHashLen, fp,
                                 st.params.keyFpLen);
    }

    void advertiseSlot()
    {
        const Params &p = st.params;
        bool presenceOk = (st.frameMask & (FRAME_PRESENCE | FRAME_STATUS)) && st.epochSet;
        uint32_t w[3] = {presenceOk ? p.weightPresence : 0, (st.frameMask & FRAME_IBEACON) ? p.weightIBeacon : 0,
                         (st.frameMask & FRAME_EDDYSTONE) ? p.weightEddystone : 0};
        int32_t total = (int32_t)(w[0] + w[1] + w[2]);
        if (total == 0) {
            adv.stop();
            return;
        }
        // Smooth weighted round robin: spreads the compatibility frames evenly between presence frames.
        int pick = 0;
        for (int i = 0; i < 3; i++) {
            wrr[i] += (int32_t)w[i];
            if (wrr[i] > wrr[pick])
                pick = i;
        }
        wrr[pick] -= total;

        uint8_t frame[FRAME_MAX];
        size_t len = 0;
        if (pick == 0) {
            if (presenceSlots % p.addressRotateSlots == 0) {
                HardwareRNG::fill(randomAddr, 6);
                randomAddr[0] &= 0x3F; // non-resolvable private address
            }
            presenceSlots++;
            bool wantStatus = (st.frameMask & FRAME_STATUS) &&
                              (!(st.frameMask & FRAME_PRESENCE) || (p.statusEvery && presenceSlots % p.statusEvery == 0));
            if (!wantStatus && buildPresence(frame, len)) {
                st.counts.presenceFrames++;
            } else if (st.frameMask & FRAME_STATUS) {
                len = buildStatus(frame);
                st.counts.statusFrames++;
            }
            if (len)
                adv.show(PresenceAdvertiser::MODE_PRESENCE, p, randomAddr, frame, len);
        } else {
            uint8_t addr[6];
            deriveStaticAddr(pick == 1 ? "HMPS-ib" : "HMPS-ed", addr);
            adv.show(pick == 1 ? PresenceAdvertiser::MODE_IBEACON : PresenceAdvertiser::MODE_EDDYSTONE, p, addr, nullptr, 0);
            if (pick == 1)
                st.counts.iBeaconFrames++;
            else
                st.counts.eddystoneFrames++;
        }
    }

    // ------------------------------------------------------------ theft (covert)
    // A moved beacon keeps advertising exactly as before; it only reports its position over LoRa.
    void theftCheck()
    {
        const Params &p = st.params;
        if (!st.homeSet || (monoMs - lastTheftCheckMs) < (uint64_t)p.theftCheckS * 1000ULL)
            return;
        lastTheftCheckMs = monoMs;
        // No fix indoors is normal, not tampering.
        if (!gpsStatus || !gpsStatus->getHasLock() || (localPosition.latitude_i == 0 && localPosition.longitude_i == 0))
            return;
        double d = distanceMeters(st.homeLat, st.homeLon, localPosition.latitude_i, localPosition.longitude_i);
        outsideFixes = d > p.theftRadiusM ? outsideFixes + 1 : 0;
        if (!st.moved && outsideFixes >= p.theftConfirmFixes) {
            st.moved = 1;
            save();
            sendMovedReport(d);
        } else if (st.moved && (monoMs - lastMovedReportMs) >= (uint64_t)p.theftReportS * 1000ULL) {
            sendMovedReport(d);
        }
    }

    void sendMovedReport(double d)
    {
        lastMovedReportMs = monoMs;
        uint8_t body[20];
        putU32(body, (uint32_t)localPosition.latitude_i);
        putU32(body + 4, (uint32_t)localPosition.longitude_i);
        putU32(body + 8, (uint32_t)d);
        putU64(body + 12, clockValid ? nowUnixMs() / 1000 : 0);
        sendUnsolicited(REPORT_MOVED, body, sizeof(body));
    }

    void sendBootReport()
    {
        uint8_t body[12];
        putU32(body, st.epochId);
        putU32(body + 4, lastTick);
        body[8] = fwVersion[0];
        body[9] = fwVersion[1];
        body[10] = fwVersion[2];
        body[11] = clockValid;
        sendUnsolicited(REPORT_BOOT, body, sizeof(body));
    }

    // ------------------------------------------------------------ LoRa send helpers
    void sendPayload(const uint8_t *buf, size_t len, NodeNum to, uint8_t channel, bool pki, const meshtastic_MeshPacket *req)
    {
        if (!len || len > meshtastic_Constants_DATA_PAYLOAD_LEN)
            return;
        meshtastic_MeshPacket *p = allocDataPacket();
        if (!p)
            return;
        memcpy(p->decoded.payload.bytes, buf, len);
        p->decoded.payload.size = len;
        if (req) {
            setReplyTo(p, *req);
        } else {
            p->to = to;
            p->channel = channel;
            p->want_ack = true;
        }
        if (pki)
            p->pki_encrypted = true;
        service->sendToMesh(p);
    }

    void reply(const meshtastic_MeshPacket &req, uint8_t cmd, uint64_t counter, uint8_t status, const uint8_t *body = nullptr,
               size_t bodyLen = 0)
    {
        uint8_t buf[meshtastic_Constants_DATA_PAYLOAD_LEN];
        size_t n = buildReply(buf, sizeof(buf), cmd | 0x80, nodeDB->getNodeNum(), counter, status, body, bodyLen, st.devicePriv,
                              st.devicePub);
        sendPayload(buf, n, 0, 0, req.pki_encrypted, &req);
    }

    void sendUnsolicited(uint8_t code, const uint8_t *body, size_t bodyLen)
    {
        if (!st.reportTo)
            return;
        uint8_t buf[meshtastic_Constants_DATA_PAYLOAD_LEN];
        size_t n = buildReply(buf, sizeof(buf), code, nodeDB->getNodeNum(), 0, ST_OK, body, bodyLen, st.devicePriv, st.devicePub);
        sendPayload(buf, n, st.reportTo, st.adminChannel, st.adminPki, nullptr);
    }

    // ------------------------------------------------------------ commands
    uint8_t applyEpoch(const EpochBody &e, Params &next, bool rotating)
    {
        if (!applyParamTlv(next, e.tlv, e.tlvLen))
            return ST_BAD_BODY;
        if (st.epochSet && e.epochId <= st.epochId)
            return ST_REJECTED; // epochs only move forward
        bool shapeChanged = next.chainLength != st.params.chainLength || next.chainValueLen != st.params.chainValueLen ||
                            next.checkpointInterval != st.params.checkpointInterval;
        if (shapeChanged && !rotating)
            return ST_REJECTED; // a different chain shape needs ROTATE_CHAIN (new anchor)
        if (e.chainTickBase < 1 || e.chainTickBase > next.chainLength)
            return ST_BAD_BODY;
        if (st.epochSet && e.hmacCounterBase <= currentCounter(currentTick()))
            return ST_REJECTED; // the HMAC counter is monotonic
        return ST_OK;
    }

    void commitEpoch(const EpochBody &e, const Params &next)
    {
        st.params = next;
        st.epochId = e.epochId;
        st.epochStartUnix = e.epochStartUnix;
        st.chainTickBase = e.chainTickBase;
        st.hmacCounterBase = e.hmacCounterBase;
        st.totpT0 = e.totpT0;
        st.epochSet = 1;
        setClock(e.nowUnix);
        lastTick = 0;
        st.reservedTick = 0;
        currentTick(); // establishes and persists the new reservation
    }

    void epochReplyBody(uint8_t body[12])
    {
        uint32_t tick = currentTick();
        putU32(body, st.epochId);
        putU32(body + 4, tick);
        putU32(body + 8, currentCounter(tick));
    }

    void statusBody(uint8_t *b, size_t &n)
    {
        uint8_t fp[32];
        adminKeyFingerprint(fp);
        uint32_t tick = currentTick();
        n = 0;
        memcpy(b, fwVersion, 3);
        n += 3;
        memcpy(b + n, fwHash, 32);
        n += 32;
        memcpy(b + n, fp, 8);
        n += 8;
        putU32(b + n, st.epochId);
        putU32(b + n + 4, tick);
        putU32(b + n + 8, st.epochSet ? currentCounter(tick) : 0);
        n += 12;
        putU16(b + n, powerStatus ? (uint16_t)powerStatus->getBatteryVoltageMv() : 0);
        b[n + 2] = powerStatus ? powerStatus->getBatteryChargePercent() : 0;
        n += 3;
        b[n++] = (st.moved ? 1 : 0) | (st.homeSet ? 2 : 0) | ((gpsStatus && gpsStatus->getHasLock()) ? 4 : 0) |
                 (chain.ready() ? 8 : 0) | (clockValid ? 16 : 0) | (st.beaconMode ? 32 : 0);
        b[n++] = st.frameMask;
        b[n++] = (uint8_t)st.params.schemeMask;
        const uint32_t *c = &st.counts.presenceFrames;
        for (int i = 0; i < 6; i++, n += 4)
            putU32(b + n, c[i]);
    }

    uint8_t provision(const AdminCommand &c, uint8_t *body, size_t &bodyLen)
    {
        const uint8_t *b = c.body;
        size_t n = c.bodyLen, o = 0;
        if (n < 32 + 1)
            return ST_BAD_BODY;
        uint8_t adminPub[32];
        memcpy(adminPub, b, 32);
        o = 32;
        uint8_t hl = b[o++];
        if (hl > 32 || o + hl + 1 > n)
            return ST_BAD_BODY;
        const uint8_t *hk = b + o;
        o += hl;
        uint8_t tl = b[o++];
        if (tl > 32 || o + tl + 1 > n)
            return ST_BAD_BODY;
        const uint8_t *tk = b + o;
        o += tl;
        uint8_t beaconMode = b[o++];

        if (!st.provisioned) {
            HardwareRNG::fill(st.devicePriv, 32);
            ed25519DerivePublic(st.devicePub, st.devicePriv);
            uint32_t me = nodeDB->getNodeNum();
            st.params.iBeaconMinor = me & 0xFFFF;
            putU32(st.params.eddystoneInstance + 2, me);
        }
        memcpy(st.adminPub, adminPub, 32);
        memcpy(st.hmacKey, hk, hl);
        st.hmacKeyLen = hl;
        memcpy(st.totpKey, tk, tl);
        st.totpKeyLen = tl;
        st.beaconMode = beaconMode ? 1 : 0;
        st.provisioned = 1;
        st.lastAdminCounter = 0;
        save();

        // The beacon owns the advertising set: turn off Meshtastic's phone Bluetooth API.
        if (st.beaconMode && config.bluetooth.enabled) {
            config.bluetooth.enabled = false;
            nodeDB->saveToDisk(SEGMENT_CONFIG);
            rebootAtMsec = millis() + 5000;
        }
        memcpy(body, st.devicePub, 32);
        putU32(body + 32, nodeDB->getNodeNum());
        bodyLen = 36;
        return ST_OK;
    }

    void handleCommand(const meshtastic_MeshPacket &mp, const AdminCommand &c)
    {
        uint8_t body[160];
        size_t bodyLen = 0;
        uint8_t status = ST_OK;

        switch (c.command) {
        case CMD_PROVISION:
            if (c.signature) { // provisioning is USB-only, never over the mesh
                status = ST_REJECTED;
                break;
            }
            status = provision(c, body, bodyLen);
            break;
        case CMD_TIME_SYNC:
            if (c.bodyLen != 8) {
                status = ST_BAD_BODY;
                break;
            }
            setClock(getU64(c.body));
            break;
        case CMD_RESYNC:
        case CMD_ROTATE_CHAIN: {
            EpochBody e;
            if (!parseEpochBody(c.body, c.bodyLen, e)) {
                status = ST_BAD_BODY;
                break;
            }
            if (chain.generating()) {
                status = ST_BUSY;
                break;
            }
            Params next = st.params;
            bool rotating = c.command == CMD_ROTATE_CHAIN;
            status = applyEpoch(e, next, rotating);
            if (status != ST_OK)
                break;
            if (rotating) {
                // Fresh on-device seed; only the anchor ever leaves the beacon.
                HardwareRNG::fill(st.seed, 32);
                st.seedSet = 1;
                if (!chain.begin(st.seed, next.chainLength, next.chainValueLen, next.checkpointInterval, next.checkpointRamMax)) {
                    status = ST_REJECTED;
                    break;
                }
                pendingRotate = {true, c.counter, getFrom(&mp), mp.channel, mp.pki_encrypted};
                status = ST_PENDING;
            }
            commitEpoch(e, next);
            if (!rotating) {
                epochReplyBody(body);
                bodyLen = 12;
            }
            break;
        }
        case CMD_SET_HOME:
            if (c.bodyLen != 17) {
                status = ST_BAD_BODY;
                break;
            }
            if (c.body[16] & 1) {
                st.homeSet = 0;
            } else {
                st.homeLat = (int32_t)getU32(c.body);
                st.homeLon = (int32_t)getU32(c.body + 4);
                st.homeSet = 1;
            }
            st.params.theftRadiusM = getU32(c.body + 8);
            st.reportTo = getU32(c.body + 12) ? getU32(c.body + 12) : getFrom(&mp);
            st.adminChannel = mp.channel;
            st.adminPki = mp.pki_encrypted;
            st.moved = 0;
            outsideFixes = 0;
            break;
        case CMD_STATUS:
            statusBody(body, bodyLen);
            break;
        case CMD_SET_FRAMES:
            if (c.bodyLen != 1) {
                status = ST_BAD_BODY;
                break;
            }
            st.frameMask = c.body[0] & 0x0F;
            break;
        case CMD_DECOMMISSION:
            decommissionPending = true;
            break;
        case CMD_ROTATE_ADMIN_KEY:
            if (c.bodyLen != 32) {
                status = ST_BAD_BODY;
                break;
            }
            memcpy(st.adminPub, c.body, 32);
            break;
        default:
            status = ST_UNKNOWN_COMMAND;
        }

        if (status == ST_OK || status == ST_PENDING) {
            st.counts.adminAccepted++;
            save();
        } else {
            st.counts.adminRejected++;
        }
        reply(mp, c.command, c.counter, status, body, bodyLen);
        if (decommissionPending) {
            decommissionPending = false;
            wipe();
        }
    }
};

ProcessMessage HotMessPresenceModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    const uint8_t *buf = mp.decoded.payload.bytes;
    size_t len = mp.decoded.payload.size;
    AdminCommand c;
    if (!parseAdminCommand(buf, len, c))
        return ProcessMessage::STOP;
    if (c.command & 0x80)
        return ProcessMessage::STOP; // a reply or report from another beacon

    // mp.from == 0 means the packet came from our own client API: with the phone Bluetooth API off,
    // that is the USB serial connection.
    bool local = mp.from == 0;
    if (!local) {
        // Remote commands must be signed by the current admin key, addressed to us, and fresh.
        // Failures are dropped silently so nobody can make the beacon spend airtime on replies.
        bool ok = st.provisioned && c.signature && c.target == nodeDB->getNodeNum() &&
                  verifyAdminCommand(buf, len, st.adminPub) && c.counter > st.lastAdminCounter;
        if (!ok) {
            st.counts.adminRejected++;
            LOG_WARN("HotMess presence: dropped admin command 0x%02x from 0x%08x", c.command, mp.from);
            return ProcessMessage::STOP;
        }
        st.lastAdminCounter = c.counter;
    } else if (c.signature && st.provisioned && !verifyAdminCommand(buf, len, st.adminPub)) {
        reply(mp, c.command, c.counter, ST_BAD_SIGNATURE);
        return ProcessMessage::STOP;
    } else if (!st.provisioned && c.command != CMD_PROVISION) {
        reply(mp, c.command, c.counter, ST_NOT_PROVISIONED);
        return ProcessMessage::STOP;
    }
    handleCommand(mp, c);
    return ProcessMessage::STOP;
}

int32_t HotMessPresenceModule::runOnce()
{
    updateMono();
    if (!st.provisioned || !st.beaconMode) {
        if (adv.owned())
            adv.stop();
        return 5000;
    }

    if (chain.generating()) {
        if (chain.generate(st.params.chainGenBatch) && pendingRotate.active) {
            uint8_t body[9 + 32];
            putU32(body, st.epochId);
            putU32(body + 4, chain.length());
            body[8] = (uint8_t)st.params.chainValueLen;
            memcpy(body + 9, chain.anchor(), st.params.chainValueLen);
            uint8_t buf[meshtastic_Constants_DATA_PAYLOAD_LEN];
            size_t n = buildReply(buf, sizeof(buf), CMD_ROTATE_CHAIN | 0x80, nodeDB->getNodeNum(), pendingRotate.counter, ST_OK,
                                  body, 9 + st.params.chainValueLen, st.devicePriv, st.devicePub);
            sendPayload(buf, n, pendingRotate.to, pendingRotate.channel, pendingRotate.pki, nullptr);
            pendingRotate.active = false;
            LOG_INFO("HotMess presence: chain ready, anchor sent");
        }
        // Keep generating in small slices so the mesh stack stays responsive.
        if (chain.generating())
            return 5;
    }

    if (!adv.owned()) {
        if (!nrf52Bluetooth || !adv.takeOver())
            return 1000; // Bluetooth stack not up yet
    }

    if (!bootReported && st.params.bootReportDelayS && monoMs >= (uint64_t)st.params.bootReportDelayS * 1000ULL) {
        bootReported = true;
        sendBootReport();
    }
    theftCheck();
    advertiseSlot();
    return (int32_t)st.params.slotMs;
}

static HotMessPresenceModule *hotMessPresenceModule;

void setupHotMessPresence()
{
    hotMessPresenceModule = new HotMessPresenceModule();
}

#else
void setupHotMessPresence() {}
#endif
