#include "configuration.h"

#if defined(ARCH_NRF52) && !defined(ARCH_NRF54L)
#include "PresenceAdvertiser.h"
#include <bluefruit.h>
#include <cstring>

namespace hmp
{

// The one advertising set the SoftDevice offers. Bluefruit configured it as handle 0.
static uint8_t advHandle = 0;

static size_t putAd(uint8_t *buf, size_t o, uint8_t type, const uint8_t *data, size_t len)
{
    if (o + 2 + len > 31)
        return o;
    buf[o] = (uint8_t)(len + 1);
    buf[o + 1] = type;
    memcpy(buf + o + 2, data, len);
    return o + 2 + len;
}

bool PresenceAdvertiser::takeOver()
{
    uint8_t enabled = 0;
    if (sd_softdevice_is_enabled(&enabled) != NRF_SUCCESS || !enabled)
        return false;
    Bluefruit.Advertising.restartOnDisconnect(false);
    Bluefruit.Advertising.stop();
    isOwned = true;
    return true;
}

void PresenceAdvertiser::stop()
{
    if (isOwned)
        sd_ble_gap_adv_stop(advHandle);
}

bool PresenceAdvertiser::show(Mode mode, const Params &p, const uint8_t addr[6], const uint8_t *frame, size_t frameLen)
{
    if (!isOwned)
        return false;
    sd_ble_gap_adv_stop(advHandle); // NRF_ERROR_INVALID_STATE when already stopped is fine

    // Alternate buffers: the SoftDevice may still hold the previous ones until reconfigured.
    bufIndex ^= 1;
    uint8_t *adv = advBuf[bufIndex];
    uint8_t *sr = srBuf[bufIndex];
    size_t advLen = 0, srLen = 0;
    const uint8_t flags = BLE_GAP_ADV_FLAG_BR_EDR_NOT_SUPPORTED;
    advLen = putAd(adv, advLen, BLE_GAP_AD_TYPE_FLAGS, &flags, 1);

    ble_gap_addr_t gapAddr;
    memset(&gapAddr, 0, sizeof(gapAddr));
    for (int i = 0; i < 6; i++)
        gapAddr.addr[i] = addr[5 - i]; // SoftDevice wants little-endian
    uint8_t type;

    if (mode == MODE_PRESENCE) {
        gapAddr.addr_type = BLE_GAP_ADDR_TYPE_RANDOM_PRIVATE_NON_RESOLVABLE;
        uint8_t md[2 + SCANRSP_MFR_PAYLOAD_MAX];
        md[0] = (uint8_t)p.companyId; // company id is little-endian on air
        md[1] = (uint8_t)(p.companyId >> 8);
        size_t first = frameLen < ADV_MFR_PAYLOAD_MAX ? frameLen : ADV_MFR_PAYLOAD_MAX;
        memcpy(md + 2, frame, first);
        advLen = putAd(adv, advLen, BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA, md, 2 + first);
        if (frameLen > first) {
            memcpy(md + 2, frame + first, frameLen - first);
            srLen = putAd(sr, 0, BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA, md, 2 + frameLen - first);
        }
        type = srLen ? BLE_GAP_ADV_TYPE_NONCONNECTABLE_SCANNABLE_UNDIRECTED : BLE_GAP_ADV_TYPE_NONCONNECTABLE_NONSCANNABLE_UNDIRECTED;
    } else if (mode == MODE_IBEACON) {
        gapAddr.addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC;
        uint8_t md[25] = {0x4C, 0x00, 0x02, 0x15};
        memcpy(md + 4, p.iBeaconUuid, 16);
        putU16(md + 20, (uint16_t)p.iBeaconMajor);
        putU16(md + 22, (uint16_t)p.iBeaconMinor);
        md[24] = (uint8_t)(int8_t)(p.txPowerDbm - 41); // measured power at 1 m, rough
        advLen = putAd(adv, advLen, BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA, md, sizeof(md));
        type = BLE_GAP_ADV_TYPE_NONCONNECTABLE_NONSCANNABLE_UNDIRECTED;
    } else {
        gapAddr.addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC;
        const uint8_t uuid[2] = {0xAA, 0xFE};
        advLen = putAd(adv, advLen, BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_COMPLETE, uuid, 2);
        uint8_t sd[22] = {0xAA, 0xFE, 0x00};
        sd[3] = (uint8_t)(int8_t)(p.txPowerDbm - 41);
        memcpy(sd + 4, p.eddystoneNamespace, 10);
        memcpy(sd + 14, p.eddystoneInstance, 6);
        advLen = putAd(adv, advLen, BLE_GAP_AD_TYPE_SERVICE_DATA, sd, sizeof(sd));
        type = BLE_GAP_ADV_TYPE_NONCONNECTABLE_NONSCANNABLE_UNDIRECTED;
    }

    if (sd_ble_gap_addr_set(&gapAddr) != NRF_SUCCESS)
        return false;

    ble_gap_adv_params_t params;
    memset(&params, 0, sizeof(params));
    params.properties.type = type;
    params.interval = (uint16_t)((p.advIntervalMs * 1000) / 625);
    params.duration = 0;
    params.filter_policy = BLE_GAP_ADV_FP_ANY;
    params.primary_phy = BLE_GAP_PHY_1MBPS;

    static ble_gap_adv_data_t data; // must outlive the call
    data.adv_data.p_data = adv;
    data.adv_data.len = (uint16_t)advLen;
    data.scan_rsp_data.p_data = srLen ? sr : nullptr;
    data.scan_rsp_data.len = (uint16_t)srLen;

    if (sd_ble_gap_adv_set_configure(&advHandle, &data, &params) != NRF_SUCCESS)
        return false;
    sd_ble_gap_tx_power_set(BLE_GAP_TX_POWER_ROLE_ADV, advHandle, (int8_t)p.txPowerDbm);
    return sd_ble_gap_adv_start(advHandle, BLE_CONN_CFG_TAG_DEFAULT) == NRF_SUCCESS;
}

} // namespace hmp
#endif
