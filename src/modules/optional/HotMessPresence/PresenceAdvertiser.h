#pragma once
#include "PresenceCore.h"
#include <cstdint>

namespace hmp
{

// Time-shares the nRF52 SoftDevice's single legacy advertising set between the custom presence
// frame (rotating non-resolvable random address, payload split over advertisement + scan response)
// and compatibility frames (iBeacon, Eddystone-UID) on their own static random addresses.
// Advertising is non-connectable, so no GATT service is reachable.
class PresenceAdvertiser
{
  public:
    enum Mode : uint8_t { MODE_PRESENCE, MODE_IBEACON, MODE_EDDYSTONE };

    // Stop whatever is advertising and take the set over. False if the SoftDevice is not up.
    bool takeOver();
    bool owned() const { return isOwned; }
    void stop();

    // One slot: stop, set address + payload, restart. `frame` is a presence/status frame for
    // MODE_PRESENCE and ignored otherwise.
    bool show(Mode mode, const Params &p, const uint8_t addr[6], const uint8_t *frame, size_t frameLen);

  private:
    bool isOwned = false;
    uint8_t bufIndex = 0;
    uint8_t advBuf[2][31];
    uint8_t srBuf[2][31];
};

} // namespace hmp
