/*
 * SPECTER, Native MeshCore Flood Repeater
 * Hardware: STM32F103C8T6 + SX1262 (DX-LR30 module)
 * Version: 1.2.0
 *
 * Pin mapping (confirmed from BoardInfo + sx1262_driver.h):
 *   SPI1 : SCK=PA5  MISO=PA6  MOSI=PA7
 *   SX1262: NSS=PA4  BUSY=PA2  NRST=PA3
 *   RF switch: TXEN=PA0  RXEN=PA1
 *   LED  : PB11 (active HIGH)
 *   UART1: TX=PA9  RX=PA10  → CH340 USB (requires ENABLE_HWSERIAL1 flag)
 *
 * Radio settings: runtime-configurable via CLI (docs/cli.md),
 * EU868 defaults: 869.618 MHz  SF8  BW 62.5 kHz  SyncWord 0x12
 *
 * CLI: USB-serial MeshCore command subset (ver, name, lat/lon, radio,
 * advert intervals, neighbors, stats, ...). See docs/cli.md.
 */

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>
#include <SHA256.h>
#include <SHA512.h>
#include <Ed25519.h>
#include <IWatchdog.h>
#include "stm32f1xx_hal.h"
#include "config.h"
#include "meshcrypto/meshcrypto.h"
#include "meshcrypto/ed_25519.h"
#include "acl.h"

// ─── Version ─────────────────────────────────────────────────────────────────
#define FW_VERSION "1.15.3"

// ─── Mesh-admin payload types (matching MeshCore) ────────────────────────────
#define PAYLOAD_TYPE_REQ        0x00   // Request (dest/src hashes + MAC)
#define PAYLOAD_TYPE_RESPONSE   0x01
#define PAYLOAD_TYPE_TXT_MSG    0x02
#define PAYLOAD_TYPE_ANON_REQ   0x07
#define PAYLOAD_TYPE_PATH       0x08   // Returned path (dest/src hashes + MAC)
// REQ request-type bytes (BaseChatMesh):
#define  REQ_GET_STATS          0x01   // repeater/server stats (get stats)
#define  REQ_GET_TELEMETRY      0x03
#define  REQ_GET_ACL            0x05
#define  REQ_GET_NEIGHBORS      0x06
#define TXT_TYPE_CLI_DATA       1
#define TXT_TYPE_CLI_COMMAND    3
#define RESP_SERVER_LOGIN_OK    0
#define ANON_REQ_TYPE_BASIC     0x03   // remote clock query (official)
static uint32_t anon_win_s = 0;
static uint8_t  anon_count = 0;

// ─── Repeater stats (REQ_TYPE_GET_STATUS response) ───────────────────────────
// Byte-exact port of the official simple_repeater RepeaterStats: 56 bytes,
// little-endian, no padding (every field is 2- or 4-byte aligned). The response
// plaintext is [sender_timestamp(4)][RepeaterStats] — the sender's ts is
// reflected back as a correlation 'tag'.
struct RepeaterStats {
    uint16_t batt_milli_volts;
    uint16_t curr_tx_queue_len;
    int16_t  noise_floor;
    int16_t  last_rssi;
    uint32_t n_packets_recv;
    uint32_t n_packets_sent;
    uint32_t total_air_time_secs;
    uint32_t total_up_time_secs;
    uint32_t n_sent_flood, n_sent_direct;
    uint32_t n_recv_flood, n_recv_direct;
    uint16_t err_events;
    int16_t  last_snr;                    // x 4
    uint16_t n_direct_dups, n_flood_dups;
    uint32_t total_rx_air_time_secs;
    uint32_t n_recv_errors;
};
static_assert(sizeof(RepeaterStats) == 56,
              "RepeaterStats must be exactly 56 bytes (byte-exact with the official)");

// Live accumulators (populated in the RX/TX paths; read by handle_req)
static int16_t  stat_last_rssi   = 0;   // last received RSSI (dBm)
static int16_t  stat_last_snr_x4 = 0;   // last received SNR (x4)
static uint32_t stat_tx_air_ms   = 0;   // cumulative TX air time (ms)
static uint32_t stat_rx_air_ms   = 0;   // cumulative RX air time (ms)
static uint32_t stat_sent_flood  = 0;
static uint32_t stat_sent_direct = 0;
static uint32_t stat_recv_flood  = 0;
static uint32_t stat_recv_direct = 0;
static uint32_t stat_direct_dups = 0;
static uint32_t stat_flood_dups  = 0;
static uint32_t stat_recv_errors = 0;   // CRC / read errors

// Noise floor (instantaneous RSSI while idle in RX): average of N quiet samples
// (below current floor + 14 dB, matching the official's SAMPLING_THRESHOLD),
// clamped to -120 dBm.
// Sampling session is triggered once every 10 minutes to minimize radio SPI polling
// and MCU wakeups. An initial session runs 5s after boot once radio is idle in RX.
#define NF_INTERVAL_MS        600000UL   // 10 minutes between sampling bursts
#define NF_BURST_SPACING_MS   100UL      // 100 ms between burst samples
#define NF_BURST_SAMPLES      10         // N subsequent samples to average
#define NF_MAX_ATTEMPTS       25         // max attempts before concluding session

static int16_t  stat_noise_floor       = 0;
static uint32_t last_nf_session_ms     = 0;
static uint32_t last_nf_sample_ms      = 0;
static uint8_t  nf_samples             = 0;
static int32_t  nf_sum                 = 0;
static uint8_t  nf_attempts            = 0;
static bool     nf_session_active      = false;
static bool     nf_initial_done        = false;

// Basic packet statistics (declared here so handle_req / the stats response can
// use them; the RX/TX paths below increment them)
uint32_t stat_rx     = 0;   // valid packets received from radio
uint32_t stat_relay  = 0;   // packets successfully relayed
uint32_t stat_drop   = 0;   // packets rejected (dedup/hops/malformed)

// ─── Pin definitions ─────────────────────────────────────────────────────────
#define PIN_NSS   PA4
#define PIN_DIO1  PC15   // Verified connected to PC15 on this HW revision (shared with LSE OSC32_OUT)
#define PIN_NRST  PA3
#define PIN_BUSY  PA2
#define PIN_TXEN  PA0
#define PIN_RXEN  PA1
#define PIN_LED   PB11
#define LED_ON    HIGH   // DX-LR30: LED anode on PB11 (active HIGH)
#define LED_OFF   LOW

// ─── Radio settings ──────────────────────────────────────────────────────────
#define LORA_PREAMBLE 8
#define LORA_SYNC   0x12         // LoRa private network

// ─── MeshCore protocol constants ─────────────────────────────────────────────
#define ROUTE_TRANSPORT_FLOOD  0x00
#define ROUTE_FLOOD            0x01
#define ROUTE_DIRECT           0x02
#define ROUTE_TRANSPORT_DIRECT 0x03
#define PAYLOAD_ADVERT         0x04
#define PAYLOAD_TYPE_TRACE     0x09
#define MAX_HOPS               64
#define MAX_PKT                256
#define MAX_PAYLOAD            184   // official MAX_PACKET_PAYLOAD: larger payloads are dropped
#define MAX_PATH_SIZE          64    // official: hop_count * hash_size <= 64 bytes
#define ADV_TYPE_REPEATER      2     // advert appdata flags & 0x0F

// ─── Timing ──────────────────────────────────────────────────────────────────
#define FIRST_ADVERT_MS        5000UL                   // 5 s after boot

// ─── Node identity ────────────────────────────────────────────────────────────
// Default: auto-generated name "SPECTER-XXXX" (in prefs defaults) + key
// derived from STM32 UID.
//
// For a fixed identity (e.g. to control the path-hash byte), set in platformio.ini:
//   -D NODE_NAME_STR=\"SPECTER-1811\"
//   -D FIXED_PRIVKEY_HEX=\"<64 hex chars>\"   ← 32-byte Ed25519 seed
//
// The path hash is always pubkey[0], so pick a seed whose public key starts
// with the desired byte. Use tools/gen_identity.py to search for one.
static uint8_t own_privkey[32];
uint8_t own_pubkey[32];
static uint8_t own_x25519_key[32];  // mesh-admin scalar = SHA512(own_privkey)[0:32] clamped
static uint8_t own_hash;     // 1-byte path hash = own_pubkey[0]

#ifdef FIXED_PRIVKEY_HEX
// ── Compile-time hex → bytes helper (constexpr-friendly for a macro) ─────────
static void hex2bin(const char* hex, uint8_t* out, int len) {
    for (int i = 0; i < len; i++) {
        uint8_t hi = hex[2*i];
        uint8_t lo = hex[2*i+1];
        hi = (hi >= 'a') ? hi-'a'+10 : (hi >= 'A') ? hi-'A'+10 : hi-'0';
        lo = (lo >= 'a') ? lo-'a'+10 : (lo >= 'A') ? lo-'A'+10 : lo-'0';
        out[i] = (hi << 4) | lo;
    }
}
#endif

static void identity_init(void) {
    // If auto-generated placeholder name, replace with UID-based one
    if (strcmp(cfg.name, DEF_NAME) == 0) {
        const uint32_t uid_lo = *(volatile uint32_t*)0x1FFFF7F0U;
        snprintf(cfg.name, sizeof(cfg.name), "SPECTER-%04X",
                 (unsigned)(uid_lo & 0xFFFF));
    }
#ifdef FIXED_PRIVKEY_HEX
    // ── Fixed identity: use pre-generated keypair with known path hash ───────
    hex2bin(FIXED_PRIVKEY_HEX, own_privkey, 32);
    Ed25519::derivePublicKey(own_pubkey, own_privkey);
#else
    // ── Auto identity: derive deterministic key from STM32 UID ───────────────
    const uint32_t uid[3] = {
        *(volatile uint32_t*)0x1FFFF7E8U,
        *(volatile uint32_t*)0x1FFFF7ECU,
        *(volatile uint32_t*)0x1FFFF7F0U,
    };
    SHA256 sha;
    sha.reset();
    const char* domain = "SPECTER-MESHCORE-KEY-V1";
    sha.update((const uint8_t*)domain, strlen(domain));
    sha.update((const uint8_t*)uid, 12);
    sha.finalize(own_privkey, 32);
    Ed25519::derivePublicKey(own_pubkey, own_privkey);
#endif
    // Derive the X25519 scalar for mesh-admin key exchange. It MUST equal the
    // Ed25519 scalar 'a' used to derive own_pubkey (SHA512(seed)[0:32] clamped),
    // so a companion computing key_exchange(their_a, our_pub) agrees with ours.
    {
        SHA512 sha512;
        sha512.reset();
        sha512.update(own_privkey, 32);
        uint8_t h[64];
        sha512.finalize(h, 64);
        h[0]  &= 0xF8;
        h[31] &= 0x7F;
        h[31] |= 0x40;
        memcpy(own_x25519_key, h, 32);
    }
    own_hash = own_pubkey[0];
}

// ─── Dedup cache (circular, 128 slots × 8-byte SHA256 fingerprint) ───────────
// Fingerprint = first 8 bytes of SHA256(ptype ‖ payload), matching the
// reference repeater.py key: packet_fingerprint(ptype_byte + payload).
#define DEDUP_SIZE 128
#define DEDUP_FP   8
static uint8_t  dedup_buf[DEDUP_SIZE][DEDUP_FP];
static uint8_t  dedup_head = 0;

// path_len >= 0 is hashed in too (TRACE only, as the official calculatePacketHash
// does: a trace can revisit the same node on its return path).
static bool dedup_seen(const uint8_t* payload, uint8_t ptype, uint8_t plen, int path_len = -1) {
    // Compute SHA256(ptype [|| path_len] || payload), keep first DEDUP_FP bytes
    uint8_t fp[DEDUP_FP];
    {
        SHA256 sha;
        sha.reset();
        sha.update(&ptype, 1);
        if (path_len >= 0) { uint8_t pl = (uint8_t)path_len; sha.update(&pl, 1); }
        sha.update(payload, plen);
        uint8_t full[32];
        sha.finalize(full, 32);
        memcpy(fp, full, DEDUP_FP);
    }
    for (int i = 0; i < DEDUP_SIZE; i++) {
        if (memcmp(dedup_buf[i], fp, DEDUP_FP) == 0) return true;
    }
    memcpy(dedup_buf[dedup_head], fp, DEDUP_FP);
    dedup_head = (dedup_head + 1) % DEDUP_SIZE;
    return false;
}

// Short fingerprint (first 4 bytes of SHA256(ptype||payload), 8 hex chars) for
// TX/RX correlation in the log: if an RX fp matches a recent TX fp, that sent
// packet is coming back (self-pickup or a peer echo/ACK).
static void short_fp(const uint8_t* payload, uint8_t ptype, uint8_t plen, char* out) {
    SHA256 sha;
    sha.reset();
    sha.update(&ptype, 1);
    sha.update(payload, plen);
    uint8_t full[32];
    sha.finalize(full, 32);
    snprintf(out, 9, "%02X%02X%02X%02X", full[0], full[1], full[2], full[3]);
}

#ifdef SP_DUMP_PAYLOAD
// Hex dump a buffer (up to `max` bytes) to the LOCAL USB console only (not the
// remote log ring), 16 bytes/line, to inspect a dropped / unexpected packet.
static void hex_dump(const uint8_t* buf, int len, int max) {
    if (len > max) len = max;
    for (int off = 0; off < len; off += 16) {
        static char hb[48];
        int n = snprintf(hb, sizeof(hb), "  %04X:", off);
        int cnt = (len - off > 16) ? 16 : (len - off);
        for (int i = 0; i < cnt && n < 46; i++)
            n += snprintf(hb + n, sizeof(hb) - n, " %02X", (unsigned)buf[off + i]);
        Serial1.println(hb);
    }
}
#endif

// RF switch (TXEN/RXEN) is driven by RadioLib via setRfSwitchPins() in
// radio_init() — standby/RX/TX states follow the radio automatically.

// LED patterns (active HIGH on PB11)
//   1 blink        = packet received
//   2 fast blinks  = relay transmitted (connectivity confirmed)
//   solid ON       = ADVERT transmitting
static void led_blink(uint8_t n, uint16_t ms) {
    for (uint8_t i = 0; i < n; i++) {
        digitalWrite(PIN_LED, LED_ON);
        delay(ms);
        digitalWrite(PIN_LED, LED_OFF);
        if (i < n - 1) delay(ms);
    }
}

// ─── Build-time Unix timestamp (clock base at boot) ─────────────────────────
// BUILD_EPOCH comes from platformio.ini (-D BUILD_EPOCH=$UNIX_TIME): real UTC.
// (The old __DATE__/__TIME__ parse used the compiler's LOCAL time as if it were
// UTC, so the clock started ahead by the build machine's UTC offset.)
// Re-sync at runtime with `time <epoch>` (USB) or `clock sync` (mesh admin).
#ifndef BUILD_EPOCH
#error "BUILD_EPOCH not set: add -D BUILD_EPOCH=$UNIX_TIME to build_flags"
#endif
static uint32_t build_unix_ts(void) { return (uint32_t)BUILD_EPOCH; }
static uint32_t ts_base = 0;   // epoch at uptime 0; set in setup(), moved by time/clock sync

// Uptime in seconds that does NOT wrap at 49.7 days like millis() does (64-bit
// ms accumulator, as the official VolatileRTCClock). Must be called at least once
// per 49 days — loop() calls it every pass.
static uint64_t uptime_ms_acc = 0;
static uint32_t uptime_prev_ms = 0;
uint32_t uptime_secs(void) {
    uint32_t n = millis();
    uptime_ms_acc += (uint32_t)(n - uptime_prev_ms);
    uptime_prev_ms = n;
    return (uint32_t)(uptime_ms_acc / 1000ULL);
}
static uint32_t now_epoch(void) { return ts_base + uptime_secs(); }

// Clock backup across resets: the STM32 backup registers (BKP DR1..DR3) survive
// software / watchdog / pin resets while VDD stays up (cleared on power loss) —
// the same idea as the official ESP32 RTC-memory backup. Without it every reboot
// rewinds the clock to build time and peers drop our adverts as replays.
#define BKP_CLOCK_MAGIC 0x5A17
static void bkp_save_time(uint32_t t) {
    BKP->DR2 = t & 0xFFFF;
    BKP->DR3 = t >> 16;
    BKP->DR1 = BKP_CLOCK_MAGIC;   // magic last: a torn write is never trusted
}
static uint32_t bkp_restore_time(void) {
    RCC->APB1ENR |= RCC_APB1ENR_PWREN | RCC_APB1ENR_BKPEN;
    PWR->CR |= PWR_CR_DBP;        // enable backup-domain writes
    if ((BKP->DR1 & 0xFFFF) != BKP_CLOCK_MAGIC) return 0;
    return ((BKP->DR3 & 0xFFFF) << 16) | (BKP->DR2 & 0xFFFF);
}

// ─── RadioLib object ─────────────────────────────────────────────────────────
SX1262 radio = new Module(PIN_NSS, PIN_DIO1, PIN_NRST, PIN_BUSY, SPI);

static bool     radio_ok         = false; // radio_init() has succeeded
static bool     rx_started       = false; // radio armed in RX (false → startReceive next loop)
static uint32_t toa255_ms        = 2000;  // airtime of a 255 B packet  (set in radio_init)
static uint32_t preamble_ms      = 50;    // preamble+header airtime  (set in radio_init)
static uint32_t max_pkt_ms       = 4000;  // airtime of a 255 B packet (set in radio_init)
static uint32_t last_radio_retry = 0;     // degraded-mode retry timer

// ─── Token-bucket RF duty cycle (matches the MeshCore Dispatcher) ────────────
// A budget of airtime (ms) refills continuously at the duty rate over a 1-hour
// window. Bursts up to the bucket are allowed; each TX consumes its measured
// airtime and is gated until enough budget is available. This is far smoother
// than a fixed per-packet silence: idle time tops the bucket up, so a burst
// after idle is fine, and the average airtime over the window stays ≤ duty.
#define DUTY_WINDOW_MS 3600000UL          // 1 h window (MeshCore standard)
static uint32_t tx_budget_ms       = 0;   // available airtime budget (ms)
static uint32_t last_budget_update = 0;   // last refill timestamp (ms)

// ─── DIO1 interrupt flag ─────────────────────────────────────────────────────
// Set by the DIO1 ISR: RxDone while receiving, TxDone while transmitting (the
// same pin — official RadioLibWrapper setFlag). The loop reads it as TX-done when
// tx_active, else as RX-done, and otherwise sleeps in __WFI().
static volatile bool dio1_flag = false;

static void on_dio1(void) {
    dio1_flag = true;
}

static bool radio_init(void) {
    SPI.begin();
    float freq_mhz = cfg.freq_khz / 1000.0f;
    float bw_khz   = cfg.bw_tenth / 10.0f;
    int state = radio.begin(freq_mhz, bw_khz, cfg.sf, cfg.cr,
                            LORA_SYNC, cfg.tx_dbm, LORA_PREAMBLE);
    if (state != RADIOLIB_ERR_NONE) {
        Serial1.print("FAILED: "); Serial1.println(state);
        return false;
    }
    radio.setRfSwitchPins(PIN_RXEN, PIN_TXEN);
    // RadioLib's begin() caps PA current at 60 mA and setOutputPower keeps it,
    // which clips output above ~17 dBm. MeshCore uses 140 mA (SX126X_CURRENT_LIMIT).
    radio.setCurrentLimit(140.0);
    radio.setCRC(2);   // CRC-16 on
    radio.setDio1Action(on_dio1);   // DIO1 (PC15) fires on RxDone / TxDone → dio1_flag
    // RX gain (reg 0x08AC): 0x96 boosted / 0x94 power-saving. The driver leaves
    // this at the chip's reset default unless told otherwise; the official
    // firmware explicitly drives it to power-saving ('off'). We match that by
    // default (cfg.rxgain = 0) so weak out-of-band LoRa noise is less likely to
    // trip RxDone and pull the CPU out of __WFI().
    radio.setRxBoostedGainMode(cfg.rxgain != 0);

    // Listen-before-talk timeouts (official calcMaxPacketMillis): how long a
    // latched preamble / valid header may mean "channel busy" before it's stale.
    uint32_t tsym_us = (10000UL << (cfg.sf & 0x0F)) / cfg.bw_tenth;
    uint32_t sf_x4   = (cfg.sf <= 6) ? 25 : 17;          // sync word + SFD
    preamble_ms = ((((uint32_t)LORA_PREAMBLE + 8) * 4 + sf_x4) * tsym_us / 4 + 999) / 1000;
    toa255_ms   = (uint32_t)(radio.getTimeOnAir(255) / 1000);
    max_pkt_ms  = toa255_ms * 8 / cfg.cr;   // a sender may use CR 4/8
    return true;
}

// ─── Build ADVERT packet (MeshCore v1 protocol with Ed25519 signature) ───────
// ⚠️  CRITICAL: MeshCore companions validate Ed25519 signatures on ADVERTs.
//     Unsigned or incorrectly signed packets are silently discarded.
//     This was the root cause of "0 repeaters" during early development.
//     See docs/development-notes.md#ed25519-signature-requirement for details.
// zero_hop: ROUTE_DIRECT with an empty path, so neighbours hear it but nobody
// relays it (official sendZeroHop). Otherwise ROUTE_FLOOD (mesh-wide).
static int build_advert(uint8_t* buf, bool zero_hop) {
    int i = 0;
    buf[i++] = (uint8_t)((zero_hop ? ROUTE_DIRECT : ROUTE_FLOOD) | (PAYLOAD_ADVERT << 2));
    // Path header: [hash_size_code(2) | hop_count(6)]. 0 hops; hash size from
    // path.hash.mode (packed in loop_detect bits [3:2]; 0=1B, 1=2B, 2=3B).
    uint8_t phm = (cfg.loop_detect >> 2) & 0x03;
    buf[i++] = (uint8_t)(phm << 6);

    // --- Payload ---
    // pubkey (32 bytes)
    memcpy(buf + i, own_pubkey, 32); i += 32;

    // timestamp (4 bytes LE): compile-time Unix base + uptime seconds
    uint32_t ts = now_epoch();
    bkp_save_time(ts);   // a reset must never rewind below an advertised timestamp
    memcpy(buf + i, &ts, 4); i += 4;

    // signature placeholder (filled in after appdata is known)
    int sig_offset = i;
    memset(buf + i, 0, 64); i += 64;

    // appdata: flags [+ lat/lon] [+ name]
    int appdata_offset = i;
    bool has_loc = (cfg.lat_micro != 0 || cfg.lon_micro != 0);
    if (has_loc) {
        buf[i++] = 0x92;  // FLAG_IS_REPEATER(0x02) | FLAG_HAS_LOCATION(0x10) | FLAG_HAS_NAME(0x80)
        int32_t lat = cfg.lat_micro;
        int32_t lon = cfg.lon_micro;
        memcpy(buf + i, &lat, 4); i += 4;
        memcpy(buf + i, &lon, 4); i += 4;
    } else {
        buf[i++] = 0x82;  // FLAG_IS_REPEATER(0x02) | FLAG_HAS_NAME(0x80)
    }
    // Name (advert limit: 23 B with location, 31 without)
    uint8_t nlen = (uint8_t)strlen(cfg.name);
    uint8_t maxn = has_loc ? 23 : 31;
    if (nlen > maxn) nlen = maxn;
    memcpy(buf + i, cfg.name, nlen); i += nlen;
    int appdata_len = i - appdata_offset;

    // Sign: message = pubkey(32) + timestamp(4) + appdata
    uint8_t msg[32 + 4 + 96];  // appdata: 1 flags + 8 GPS + 31 name = 40 bytes max
    int mlen = 0;
    memcpy(msg + mlen, own_pubkey, 32);           mlen += 32;
    memcpy(msg + mlen, buf + 2 + 32, 4);          mlen += 4;   // timestamp from buf
    memcpy(msg + mlen, buf + appdata_offset, appdata_len); mlen += appdata_len;
    Ed25519::sign(buf + sig_offset, own_privkey, own_pubkey, msg, mlen);

    // Mark our own advert seen (official markSeen on send): a flood copy relayed
    // back to us is then dropped instead of re-relayed.
    dedup_seen(buf + 2, PAYLOAD_ADVERT, (uint8_t)(i - 2));
    return i;
}

// ─── Flood-relay retransmit delay (collision avoidance) ─────────────────────
// The official spreads out retransmissions of the same FLOOD packet by
// different repeaters with a random delay scaled to the packet airtime
// (_rng->nextInt(0,5) * airtime*52/50/2). SPECTER has no hardware RNG (STM32F103
// "basic" line) and no RTC (millis() is uptime, identical across nodes at the
// same uptime), so seed an LCG from the unique 96-bit STM32 UID — each chip gets
// a different sequence, so simultaneous retransmissions diverge.
// relay_delay_x10 / relay_pri: set by process_pkt for the relay it returns —
// txdelay (flood) or direct.txdelay (direct/trace), and the official queue
// priority (direct 0, flood = new hop count, trace 5).
static uint32_t rng_state       = 1;
static uint8_t  relay_delay_x10 = 0;
static uint8_t  relay_pri       = 0;
static void rng_seed_uid(void) {
    const uint32_t uid[3] = {
        *(volatile uint32_t*)0x1FFFF7E8U,
        *(volatile uint32_t*)0x1FFFF7ECU,
        *(volatile uint32_t*)0x1FFFF7F0U,
    };
    rng_state = (uid[0] * 2654435761u) ^ (uid[1] * 2246822519u) ^ (uid[2] * 3266489917u);
    if (rng_state == 0) rng_state = 1;
}
static uint32_t rng_next(void) {
    rng_state = rng_state * 1664525u + 1013904223u;   // Numerical Recipes LCG
    return rng_state;
}
static uint32_t rng_range(uint32_t max) {   // [0, max)
    return max ? (rng_next() % max) : 0;
}

// ─── Token-bucket duty-cycle helpers ────────────────────────────────────────
// Refill the budget for the elapsed time since the last update.
// Integer fixed-point (no float); 64-bit intermediates for the window math.
// Called every loop pass while a TX is pending, so elapsed is often 1-2 ms:
// only the time actually converted into budget is consumed from the clock (the
// remainder carries over), otherwise 1 ms x 10 % = 0 would never refill.
static bool duty_limited(void) { return cfg.dutycycle > 0 && cfg.dutycycle < 100; }
static void updateTxBudget(void) {
    uint32_t now = millis();
    if (!duty_limited()) { last_budget_update = now; return; }
    uint32_t elapsed = now - last_budget_update;
    uint32_t refill  = (uint32_t)(((uint64_t)elapsed * cfg.dutycycle) / 100);
    if (refill == 0) return;
    last_budget_update += (uint32_t)(((uint64_t)refill * 100) / cfg.dutycycle);
    uint32_t max_budget = (uint32_t)(((uint64_t)DUTY_WINDOW_MS * cfg.dutycycle) / 100);
    tx_budget_ms += refill;
    if (tx_budget_ms > max_budget) { tx_budget_ms = max_budget; last_budget_update = now; }
}

static void slog(const char* fmt, ...);   // fwd: important → log ring + USB
static void dlog(const char* fmt, ...);   // fwd: verbose → USB only

// Offset of the path-header byte: route types TRANSPORT_FLOOD / TRANSPORT_DIRECT
// carry 4 bytes of transport codes between the header and the path (official
// Packet::hasTransportCodes / readFrom).
static int path_hdr_offset(uint8_t header) {
    uint8_t r = header & 0x03;
    return (r == ROUTE_TRANSPORT_FLOOD || r == ROUTE_TRANSPORT_DIRECT) ? 5 : 1;
}

static uint32_t toa_ms(int len) { return (uint32_t)(radio.getTimeOnAir(len) / 1000); }

// Retransmit delay: random in [0, 5 * airtime * factor] (official
// getRetransmitDelay / getDirectRetransmitDelay; factor = txdelay x10).
static uint32_t retransmit_delay(int len, uint8_t factor_x10) {
    uint32_t t = toa_ms(len) * factor_x10 / 10u;
    return rng_range(5u * t + 1u);
}

// ─── Outbound queue + non-blocking TX scheduler (official Dispatcher) ─────────
// Packets are queued with a priority (lower = sooner: direct 0, own flood 1,
// PATH 2, advert 3, flood relay = hop count, trace 5) and a send-at time. The
// radio keeps RECEIVING while packets wait (retransmit delay, duty-cycle budget,
// busy channel) and the CPU sleeps in __WFI() instead of busy-waiting in
// delay(); TX itself is startTransmit() + DIO1 TxDone, not a blocking poll.
#define TXQ_LEN 8
static struct { uint8_t len, pri; uint32_t at; uint8_t buf[255]; } txq[TXQ_LEN];   // len 0 = free
// Official error-event bits (Dispatcher.h), reported by stats-core / GET_STATS.
#define ERR_EVENT_FULL            (1 << 0)
#define ERR_EVENT_CAD_TIMEOUT     (1 << 1)
#define ERR_EVENT_STARTRX_TIMEOUT (1 << 2)
static uint16_t err_flags    = 0;
static bool     tx_active    = false;   // a startTransmit() is in flight
static uint8_t  tx_route     = 0;
static uint32_t tx_start_ms  = 0, tx_expiry_ms = 0;
static uint32_t next_tx_ms   = 0;       // earliest next TX (budget / busy channel)
static uint32_t busy_start   = 0;       // channel-busy streak start (0 = none)
static uint32_t act_since    = 0;       // first sight of the current preamble/header

static bool tx_enqueue(const uint8_t* buf, int len, uint8_t pri, uint32_t delay_ms) {
    if (len <= 0 || len > 255) return false;
    for (int i = 0; i < TXQ_LEN; i++) {
        if (txq[i].len) continue;
        memcpy(txq[i].buf, buf, len);
        txq[i].len = (uint8_t)len;
        txq[i].pri = pri;
        txq[i].at  = millis() + delay_ms;
        return true;
    }
    err_flags |= ERR_EVENT_FULL;   // official: packet pool exhausted → dropped
    slog("TX queue full");
    return false;
}
static int txq_count(void) { int n = 0; for (int i = 0; i < TXQ_LEN; i++) if (txq[i].len) n++; return n; }
// Most important due packet (lowest priority, then earliest), or -1.
static int txq_next_due(uint32_t now) {
    int best = -1;
    for (int i = 0; i < TXQ_LEN; i++) {
        if (!txq[i].len || (int32_t)(now - txq[i].at) < 0) continue;
        if (best < 0 || txq[i].pri < txq[best].pri ||
            (txq[i].pri == txq[best].pri && (int32_t)(txq[i].at - txq[best].at) < 0)) best = i;
    }
    return best;
}

// Listen-before-talk (official CustomSX1262::isReceiving): a preamble or valid
// header latched in the IRQ status means another node is transmitting. Stale
// flags (noise-triggered preamble, a header whose packet never completed) are
// cleared after the preamble / max-packet airtime.
static bool channel_busy(uint32_t now) {
    const uint32_t ACT = RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX126X_IRQ_HEADER_VALID;
    uint32_t irq = radio.getIrqFlags();
    if (irq & RADIOLIB_SX126X_IRQ_HEADER_ERR) {
        radio.clearIrqFlags(ACT | RADIOLIB_SX126X_IRQ_HEADER_ERR | RADIOLIB_SX126X_IRQ_SYNC_WORD_VALID);
        act_since = 0;
        return false;
    }
    if (!(irq & ACT)) { act_since = 0; return false; }
    if (!act_since) act_since = now;
    uint32_t lim = (irq & RADIOLIB_SX126X_IRQ_HEADER_VALID) ? max_pkt_ms : preamble_ms;
    if (now - act_since > lim) {
        radio.clearIrqFlags(ACT | RADIOLIB_SX126X_IRQ_SYNC_WORD_VALID);
        act_since = 0;
        return false;
    }
    return true;
}

// Start the next due packet if budget, timing and channel allow (official
// Dispatcher::checkSend). Called while receiving.
static void check_send(uint32_t now) {
    int idx = txq_next_due(now);
    if (idx < 0) return;

    if (duty_limited()) {   // need >= half a max-size packet of budget
        updateTxBudget();
        uint32_t need = toa255_ms / 2;   // official MIN_TX_BUDGET_AIRTIME_DIV
        if (tx_budget_ms < need) {
            next_tx_ms = now + (uint32_t)(((uint64_t)(need - tx_budget_ms) * 100) / cfg.dutycycle);
            return;
        }
    }
    if ((int32_t)(now - next_tx_ms) < 0) return;
    if (channel_busy(now)) {
        if (!busy_start) busy_start = now;
        if (now - busy_start <= 4000) { next_tx_ms = now + 200; return; }   // retry in 200 ms
        err_flags |= ERR_EVENT_CAD_TIMEOUT;   // busy > 4 s: radio may be stuck, send anyway
    }
    busy_start = 0;

    const uint8_t* buf = txq[idx].buf;
    int len = txq[idx].len;
    if (rx_ring_log_enabled()) {   // TX log (RX/TX correlation by fingerprint)
        int ph = path_hdr_offset(buf[0]);
        int pb = (buf[ph] & 0x3F) * (((buf[ph] >> 6) & 0x03) + 1);
        if (len >= ph + 1 + pb + 2) {
            const uint8_t* pl = buf + ph + 1 + pb;
            char fp[9];
            short_fp(pl, (buf[0] >> 2) & 0x0F, (uint8_t)(len - ph - 1 - pb), fp);
            dlog("TX p=%d d=%02X s=%02X hc=%d fp=%s", (buf[0] >> 2) & 0x0F, pl[0], pl[1], buf[ph] & 0x3F, fp);
        }
    }
    dio1_flag = false;
    int st = radio.startTransmit(buf, len);   // copies into the radio's buffer
    tx_route = buf[0] & 0x03;
    txq[idx].len = 0;                         // slot free again
    if (st != RADIOLIB_ERR_NONE) { slog("TX start err %d", st); rx_started = false; return; }
    tx_active    = true;
    tx_start_ms  = now;
    tx_expiry_ms = now + toa_ms(len) * 3 / 2;   // official outbound_expiry
    digitalWrite(PIN_LED, LED_ON);              // LED on while transmitting
}

// TX in flight: finish on TxDone (DIO1) or timeout, account airtime + budget
// (official Dispatcher::loop outbound block), then go back to RX.
static void check_tx_done(uint32_t now) {
    bool done = dio1_flag;
    if (!done && (int32_t)(now - tx_expiry_ms) <= 0) return;
    dio1_flag = false;
    radio.finishTransmit();
    tx_active  = false;
    rx_started = false;
    digitalWrite(PIN_LED, LED_OFF);
    if (!done) { slog("TX timeout"); return; }
    uint32_t t = now - tx_start_ms;
    stat_tx_air_ms += t;
    if (tx_route == ROUTE_DIRECT || tx_route == ROUTE_TRANSPORT_DIRECT) stat_sent_direct++;
    else                                                              stat_sent_flood++;
    if (duty_limited()) {
        updateTxBudget();
        tx_budget_ms = (tx_budget_ms > t) ? tx_budget_ms - t : 0;
        next_tx_ms = now;
        if (tx_budget_ms < 100)   // official MIN_TX_BUDGET_RESERVE_MS
            next_tx_ms += (uint32_t)(((uint64_t)(100 - tx_budget_ms) * 100) / cfg.dutycycle);
    }
}

// ─── Process received flood packet ───────────────────────────────────────────
// Returns true if a relay packet should be sent (writes it to relay_buf/relay_len)
#include <stdarg.h>
// Important event: goes to the remote log ring (via `log`) AND the local USB
// console. Keep terse — the ring is exposed over the mesh.
static void slog(const char* fmt, ...) {
    char buf[72];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    console_log(buf);
    Serial1.println(buf);
}
// Verbose diagnostic: local USB console only (NOT the remote log ring), and only
// while `log start` is on — official packet logging is off by default too, and
// a silent UART keeps the CPU asleep instead of waiting on a 64 B TX buffer.
static void dlog(const char* fmt, ...) {
    if (!rx_ring_log_enabled()) return;
    char buf[80];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    Serial1.println(buf);
}
// Per-packet RX line: USB console + remote ring, only while `log start` is on
// (official _logging gate, logRx). Off by default.
static void rxlog(const char* fmt, ...) {
    if (!rx_ring_log_enabled()) return;
    char buf[72];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    Serial1.println(buf);
    console_log(buf);
}

static uint8_t relay_buf[MAX_PKT];
static int     relay_len = 0;

// Inbound packet context for the admin handlers (set by process_pkt): how the
// request arrived decides how the reply is routed.
static struct { bool flood; uint8_t path_hdr; const uint8_t* path; } rx_ctx;

// Official reply delays (simple_repeater): let the request's own flood settle.
#define SERVER_RESPONSE_DELAY   300
#define CLI_REPLY_DELAY_MILLIS  600

// ─── Mesh-admin: encrypted reply, routed like the official ──────────────────
//   path_return (request came by flood): a PATH packet, flooded, carrying the
//     path the request took + the reply as 'extra' — the client learns the
//     route to us and answers with its own PATH, giving us out_path.
//   else out_path known: DIRECT along it (no flood at all).
//   else: flood.
// Payload = [dest_hash][src_hash][MAC(2)+AES(data)].
static void admin_reply(AclEntry* e, uint8_t ptype, const uint8_t* data, int data_len,
                        bool path_return, uint32_t delay_ms) {
    if (!radio_ok) return;
    static uint8_t plain[MAX_PAYLOAD];
    static uint8_t b[MAX_PKT];
    uint8_t ptype_out = ptype;
    if (path_return) {
        uint8_t ph = rx_ctx.path_hdr;
        int pbytes = (ph & 0x3F) * (((ph >> 6) & 0x03) + 1);
        // official createPathReturn limit: path + extra + 5 <= MAX_COMBINED_PATH (166)
        if (pbytes + data_len + 5 <= MAX_PAYLOAD - 2 - 16) {
            int k = 0;
            plain[k++] = ph;
            memcpy(plain + k, rx_ctx.path, pbytes); k += pbytes;
            plain[k++] = ptype;                   // extra_type
            memcpy(plain + k, data, data_len); k += data_len;
            data = plain; data_len = k;
            ptype_out = PAYLOAD_TYPE_PATH;
        } else {
            path_return = false;                  // too long for a PATH: plain reply
        }
    }
    // Official MAX_PACKET_PAYLOAD = 184: 4 + round16(data_len) must fit.
    if (data_len > 176) data_len = 176;
    bool direct = !path_return && e->out_path_len != ACL_OUT_PATH_UNKNOWN;
    int n = 0;
    b[n++] = (uint8_t)((direct ? ROUTE_DIRECT : ROUTE_FLOOD) | (ptype_out << 2));
    if (direct) {
        int pb = (e->out_path_len & 0x3F) * (((e->out_path_len >> 6) & 0x03) + 1);
        b[n++] = e->out_path_len;
        memcpy(b + n, e->out_path, pb); n += pb;
    } else {
        b[n++] = (uint8_t)(rx_ctx.path_hdr & 0xC0);   // flood, 0 hops, request's hash size
    }
    int pl0 = n;
    b[n++] = e->pub[0];             // dest_hash (the client)
    b[n++] = own_hash;              // src_hash (us)
    n += mesh_encrypt_then_mac(e->secret, b + n, data, data_len);
    // Mark our own TX as seen (official markSeen): a copy looping back through
    // another repeater is deduped instead of re-relayed.
    dedup_seen(b + pl0, ptype_out, (uint8_t)(n - pl0));
    uint8_t pri = direct ? (ptype_out == PAYLOAD_TYPE_PATH ? 1 : 0)
                         : (ptype_out == PAYLOAD_TYPE_PATH ? 2 : 1);
    tx_enqueue(b, n, pri, delay_ms);
}

// Decrypted-plaintext buffer shared by the admin handlers (never concurrent).
// One byte past MAX_PAYLOAD so the plaintext can always be NUL-terminated.
static uint8_t dec_buf[MAX_PAYLOAD + 1];

// Verify MAC + decrypt into dec_buf (bounded), NUL-terminate. Returns the
// plaintext length, or 0 on MAC failure / malformed / oversized input.
static int admin_decrypt(const uint8_t* secret, const uint8_t* mac_data, int enc_len) {
    int len = mesh_mac_then_decrypt(secret, dec_buf, MAX_PAYLOAD, mac_data, enc_len);
    dec_buf[len] = 0;
    return len;
}

// Find the session whose secret decrypts this REQ/TXT_MSG. src is only a 1-byte
// hash, so try every active session with that first byte (the official tries
// all matching peers). Returns the session (plaintext in dec_buf) or NULL.
static AclEntry* session_decrypt(uint8_t src_hash, const uint8_t* mac_data, int enc_len, int* out_len) {
    for (int i = 0; i < ACL_MAX; i++) {
        AclEntry* e = (AclEntry*)acl_at(i);
        if (!e || !e->active || e->pub[0] != src_hash) continue;
        int len = admin_decrypt(e->secret, mac_data, enc_len);
        if (len > 0) { *out_len = len; return e; }
    }
    return 0;
}

// Login (ANON_REQ): payload = [dest_hash][sender_pub(32)][MAC+AES(ts(4)+password)]
// Returns true once the MAC verifies (the packet was for us, even if the login
// is then refused); false means "not ours" and the caller relays it.
static bool handle_anon_req(const uint8_t* pl, int plen) {
    if (plen < 1 + 32 + 2 + 1) return false;
    const uint8_t* sender_pub = pl + 1;
    const uint8_t* macData    = pl + 1 + 32;
    int enc_len = plen - 1 - 32;

    uint8_t secret[32];
    ed25519_key_exchange(secret, sender_pub, own_x25519_key);

    int len = admin_decrypt(secret, macData, enc_len);
    if (len == 0) return false;
    if (len < 5) return true;
    uint8_t* data = dec_buf;
    uint32_t their_ts; memcpy(&their_ts, data, 4);
    const char* password = (const char*)(data + 4);

    // Typed anon request (official: data[4] in 1..31, DIRECT only, 4 per 3 min).
    // ponytail: only ANON_REQ_TYPE_BASIC (remote clock); REGIONS/OWNER get no
    // reply, add them if clients need them.
    if (data[4] != 0 && data[4] < ' ') {
        if (data[4] != ANON_REQ_TYPE_BASIC || rx_ctx.flood || len < 6) return true;
        uint8_t rpl = data[5];
        int rpb = (rpl & 0x3F) * (((rpl >> 6) & 0x03) + 1);
        if (((rpl >> 6) & 0x03) == 3 || rpb > MAX_PATH_SIZE || 6 + rpb > len) return true;
        uint32_t now_s = uptime_secs();
        if (now_s - anon_win_s >= 180) { anon_win_s = now_s; anon_count = 0; }
        if (anon_count >= 4) return true;
        anon_count++;
        static AclEntry tmp;                       // reply target: supplied path, no session
        memcpy(tmp.pub, sender_pub, sizeof(tmp.pub));
        memcpy(tmp.secret, secret, sizeof(tmp.secret));
        tmp.out_path_len = rpl;
        memcpy(tmp.out_path, data + 6, rpb);
        uint8_t r[9];
        uint32_t now = now_epoch();
        memcpy(r, &their_ts, 4);                   // sender ts as tag
        memcpy(r + 4, &now, 4);                    // our clock
        r[8] = cfg.repeat_en ? 0 : 0x80;           // features: 0x80 = forwarding disabled
        admin_reply(&tmp, PAYLOAD_TYPE_RESPONSE, r, sizeof(r), false, SERVER_RESPONSE_DELAY);
        return true;
    }

    uint8_t perms = 0xFF;
    if (password[0] == 0) {
        AclEntry* e = acl_by_pub(sender_pub);
        if (e) {
            perms = e->perms;              // blank pw re-authenticates an existing session
        } else if (adm.guest_password[0] == 0) {
            perms = PERM_READ;             // guest pw unset → blank pw gets guest (read-only),
                                           // so the app's guest/Repeater-Status path works out of the box
        } else {
            return true;                   // blank pw, no existing session, guest pw set → reject
        }
    } else if (adm.admin_password[0] && strcmp(password, (const char*)adm.admin_password) == 0) {
        perms = PERM_ADMIN;
    } else if (adm.guest_password[0] && strcmp(password, (const char*)adm.guest_password) == 0) {
        perms = PERM_READ;                  // guest = read-only (no set, no reboot/erase)
    } else {
        return true;                       // bad password
    }

    AclEntry* e = acl_add(sender_pub);     // evicts the least-active non-admin if full
    if (their_ts <= e->last_ts) return true;    // login replay guard (before touching the entry)
    e->perms = perms;
    memcpy(e->secret, secret, sizeof(e->secret));
    e->last_ts = their_ts;
    e->last_activity_ms = millis();
    if (rx_ctx.flood) e->out_path_len = ACL_OUT_PATH_UNKNOWN;   // official: rediscover the route

    // login RESPONSE: [ts(4)][RESP_SERVER_LOGIN_OK=0][0][is_admin][perms][rand(4)][ver_level]
    static uint8_t resp[13];
    uint32_t now = now_epoch();
    memcpy(resp, &now, 4);
    resp[4]  = RESP_SERVER_LOGIN_OK;
    resp[5]  = 0;
    resp[6]  = (perms == PERM_ADMIN) ? 1 : 0;
    resp[7]  = perms;
    resp[8]  = (uint8_t)(millis() & 0xFF);
    resp[9]  = (uint8_t)((millis() >> 8) & 0xFF);
    resp[10] = e->pub[0];
    resp[11] = e->pub[1];
    resp[12] = 0;                          // FIRMWARE_VER_LEVEL (informational)
    // Official chooseReplyRoute: flood login → PATH return; direct → out_path or flood.
    admin_reply(e, PAYLOAD_TYPE_RESPONSE, resp, sizeof(resp), rx_ctx.flood, SERVER_RESPONSE_DELAY);

    slog("login %02X %s", e->pub[0], perms == PERM_ADMIN ? "admin" : "guest");
    return true;
}

// Minimum permission a CLI command requires (ACL gate). Fail-safe: unknown → ADMIN.
static uint8_t cmd_perm_needed(const char* text) {
    while (*text == ' ' || *text == '\t') text++;
    // Secrets: anything mentioning a password (get/set admin.password,
    // guest.password, "password") is admin-only — whatever the spacing.
    if (strstr(text, "password"))       return PERM_ADMIN;
    // Calibration writes: admin or local-serial only (stricter than the generic
    // "set"→READWRITE and "battery"→READ rules further down).
    if (!strncmp(text, "battery.charged", 15)) return PERM_ADMIN;
    if (!strncmp(text, "set battery.vref", 16)) return PERM_ADMIN;
    if (!strncmp(text, "set temp.offset", 15))  return PERM_ADMIN;
    if (!strncmp(text, "get", 3))       return PERM_READ;
    if (!strncmp(text, "ver", 3))       return PERM_READ;
    if (!strncmp(text, "board", 5))     return PERM_READ;
    if (!strncmp(text, "role", 4))      return PERM_READ;
    // Bare "clock" / "log" read; any argument ("clock sync", "log clear") writes.
    if (!strncmp(text, "clock", 5))     return text[5] ? PERM_ADMIN : PERM_READ;
    if (!strncmp(text, "stats", 5))     return PERM_READ;
    if (!strncmp(text, "battery", 7))   return PERM_READ;
    if (!strncmp(text, "neighbors", 9)) return PERM_READ;
    if (!strncmp(text, "log", 3))       return text[3] ? PERM_ADMIN : PERM_READ;
    if (!strncmp(text, "acl", 3))       return PERM_READ;
    if (!strncmp(text, "set", 3))       return PERM_READWRITE;
    // reboot / erase / dfu and anything unrecognized require full admin
    return PERM_ADMIN;
}

// ─── Supply voltage (VDDA) via the internal VREFINT ──────────────────────────
// Measures the analog supply with NO external divider: the ADC reference IS
// VDDA, so reading the fixed ~1.2 V internal VREFINT against it inverts to the
// supply voltage. The battery sits on the 3V3 rail (board tolerates up to
// 4 V VCC), so VDDA ≈ battery voltage with no over-range risk:
//     VDDA_mV = VREFINT_MV * 4096 / VREFINT_ADC
// VREFINT is per-chip (datasheet nominal 1.20 V, range 1.16–1.24 V). The F103
// has no factory calibration word we trust here, so it lives in cal.vrefint_mv
// (prefs.cpp) and is calibrated per board: `battery.charged` treats the current
// reading as a fully-charged 4.2 V pack, or `set battery.vref <mV>` sets it
// directly. The default (cal_defaults) is 1180 mV, measured on a reference board.
// (Caveat: the pack drifts upward while charging over USB, so calibrate against
// a known-good reference at the same charge state.)

// Calibrated 25C ref voltage, needed for temperature measurement, default 1430 
// 1.34 – 1.52 V (±90 mV → ±21°C!)
#define V25REF_MV 1370

// measure_vdda_mv()  → the true analog supply (VDDA).
// measure_battery_mv() → VDDA + SHOTTKY_DROP_MV (pack voltage with the mod).
// measure_mcu_temp() → scales its ADC against the clean VDDA (not the battery).
// The ADC is powered on only for the measurement (a few ms), then off again,
// to keep idle current low.

// ---- Combined VREFINT (ch17) + temp-sensor (ch16) sampling ------------------
// Both channels are read in a SINGLE ADC power-on cycle, averaged over
// ADC_SAMPLES readings to smooth sampling noise, and cached with a timestamp.
// The metrics below derive from the cache and refresh it only if it's older
// than ADC_MAX_AGE_MS — so a battery+temp read is ONE ADC cycle (not the old
// 2-3), and repeated reads within the window share the same sample.

#define ADC_SAMPLES     8                          // per-channel average (4-8)
#define ADC_MAX_AGE_MS  (60UL * 1000UL)             // refresh the sample if older (1 min)

typedef struct {
    uint16_t vref_raw;   // averaged ch17 (0-4095)
    uint16_t temp_raw;   // averaged ch16 (0-4095)
    uint32_t ts_ms;      // millis() at sample time
    bool     valid;      // true once sampled
} adc_cache_t;

static adc_cache_t s_adc;

// Read one channel (single-rank sequence; rank set per call). Reading DR clears
// EOC. Bounded wait so a stuck ADC can't hang the loop.
static uint16_t adc_read_ch(uint8_t ch) {
    ADC1->SQR3 = ch;
    ADC1->CR2 |= ADC_CR2_SWSTART;
    for (int i = 0; i < 100000 && !(ADC1->SR & ADC_SR_EOC); i++) {}
    return (uint16_t)ADC1->DR;
}

// Power on ADC1, discard the initial conversions, then average ADC_SAMPLES
// readings of ch17 (VREFINT) and ch16 (temp) in one cycle. Cache + timestamp.
static void adc_sample(void) {
    RCC->APB2ENR |= RCC_APB2ENR_ADC1EN;    // ADC1 interface clock
    ADC1->CR2 = 0;
    ADC1->CR1 = 0;
    // VREFINT + temp-sensor paths + EXTSEL=SWSTART(0b111) + EXTTRIG + power on.
    // EXTSEL/EXTTRIG must select the software trigger, otherwise the SWSTART
    // write is a no-op, EOC never sets, and DR reads 0.
    ADC1->CR2 = ADC_CR2_TSVREFE
              | ADC_CR2_EXTSEL
              | ADC_CR2_EXTTRIG
              | ADC_CR2_ADON;
    delay(2);                              // tSTAB / power-up settle
    ADC1->SMPR1 = (ADC1->SMPR1 & ~(ADC_SMPR1_SMP17 | ADC_SMPR1_SMP16))
                | ADC_SMPR1_SMP17 | ADC_SMPR1_SMP16;   // 247.5 cyc, both ch
    ADC1->SQR2 = 0;
    ADC1->SQR1 = 0;                        // scan length = 1 (channel set per read)

    for (int i = 0; i < 3; i++) (void)adc_read_ch(17);   // discard dummies
    uint32_t s17 = 0, s16 = 0;
    for (int i = 0; i < ADC_SAMPLES; i++) {
        s17 += adc_read_ch(17);
        s16 += adc_read_ch(16);
    }
    ADC1->CR2 = 0;                         // power off
    s_adc.vref_raw = (uint16_t)(s17 / ADC_SAMPLES);
    s_adc.temp_raw = (uint16_t)(s16 / ADC_SAMPLES);
    s_adc.ts_ms    = millis();
    s_adc.valid    = true;
}

// Re-sample if we never have one or it's older than ADC_MAX_AGE_MS.
static void adc_refresh_if_stale(void) {
    if (!s_adc.valid || (millis() - s_adc.ts_ms) > ADC_MAX_AGE_MS) adc_sample();
}

// Clean analog supply (VDDA) in mV = vrefint_mv * 4096 / vref_raw. 0 on failure.
static uint32_t adc_vdda_mv(void) {
    if (!s_adc.valid || s_adc.vref_raw == 0) return 0;
    return (uint32_t)cal.vrefint_mv * 4096UL / s_adc.vref_raw;
}

// Clean analog supply (VDDA) in mV, from the internal VREFINT (cal.vrefint_mv).
uint16_t measure_vdda_mv(void) {
    adc_refresh_if_stale();
    uint32_t v = adc_vdda_mv();
    return (uint16_t)(v > 65535 ? 65535 : v);
}

// Pack voltage with the battery mod: VDDA + the 1N5817 Schottky drop.
uint16_t measure_battery_mv(void) {
    adc_refresh_if_stale();
    uint32_t vdda = adc_vdda_mv();
    if (vdda == 0) return 0;
    return (uint16_t)(vdda + SHOTTKY_DROP_MV);
}

// MCU die temperature (°C) from the internal sensor (ch16), scaled against the
// clean VDDA. T = (V25 - Vsense) / 4.3 mV/°C + 25 (STM32F103 datasheet). -127 on
// failure. Integer math (newlib-nano has no float printf).
int16_t measure_mcu_temp(void) {
    adc_refresh_if_stale();
    uint32_t vdda = adc_vdda_mv();
    if (vdda == 0) return -127;
    int32_t vsense_x10 = (int32_t)s_adc.temp_raw * (int32_t)vdda * 10 / 4096;
    int32_t temp_x10   = ((int32_t)V25REF_MV * 10 - vsense_x10) * 10 / 43 + 250;
    return (int16_t)((temp_x10 + 5) / 10) + cal.temp_offset_c;
}

// REQ (p=0): payload = [dest_hash][src_hash][MAC+AES(ts(4)+req_type(1)+fields)].
// Decrypt with the session secret, dispatch by request type, and reply with a
// RESPONSE (p=1) = [their_ts(4)][response_data]. Implements REQ_TYPE_GET_STATUS
// (0x01, guest-accessible) → RepeaterStats; other types are logged + dumped.
// Returns true if a session decrypted it (ours), false → caller relays it.
static bool handle_req(const uint8_t* pl, int plen) {
    if (plen < 2 + 2 + 5) { slog("REQ short"); return false; }
    uint8_t src_hash = pl[1];
    int len = 0;
    AclEntry* e = session_decrypt(src_hash, pl + 2, plen - 2, &len);
    if (!e) { slog("REQ no sess/MAC"); return false; }
    if (len < 5) return true;
    uint8_t* data = dec_buf;

    uint32_t their_ts; memcpy(&their_ts, data, 4);   // request timestamp
    // Replay guard (official: timestamp must be strictly newer for a REQ)
    if (their_ts <= e->last_ts) { slog("REQ replay"); return true; }
    uint8_t req_type = data[4];
    dlog("REQ src=%02X type=0x%02X", src_hash, req_type);

    static uint8_t resp[64];
    if (req_type == REQ_GET_STATS) {
        // Reply = [their_ts(4)][RepeaterStats(56)] — reflect the request ts as
        // the correlation tag, then the stats (guest-accessible).
        memcpy(resp, data, 4);
        RepeaterStats s;
        s.batt_milli_volts       = measure_battery_mv(); // pack voltage (mV)
        s.curr_tx_queue_len      = (uint16_t)txq_count();
        s.noise_floor            = stat_noise_floor;
        s.last_rssi              = stat_last_rssi;
        s.n_packets_recv         = stat_rx;
        s.n_packets_sent         = stat_sent_flood + stat_sent_direct;
        s.total_air_time_secs    = stat_tx_air_ms / 1000;
        s.total_up_time_secs     = uptime_secs();
        s.n_sent_flood           = stat_sent_flood;
        s.n_sent_direct          = stat_sent_direct;
        s.n_recv_flood           = stat_recv_flood;
        s.n_recv_direct          = stat_recv_direct;
        s.err_events             = err_flags;         // official ERR_EVENT_* bits
        s.last_snr               = stat_last_snr_x4;
        s.n_direct_dups          = (uint16_t)stat_direct_dups;
        s.n_flood_dups           = (uint16_t)stat_flood_dups;
        s.total_rx_air_time_secs = stat_rx_air_ms / 1000;
        s.n_recv_errors          = stat_recv_errors;
        memcpy(resp + 4, &s, sizeof(s));
        admin_reply(e, PAYLOAD_TYPE_RESPONSE, resp, 4 + sizeof(s), rx_ctx.flood, SERVER_RESPONSE_DELAY);
        e->last_activity_ms = millis();
        e->last_ts = their_ts;
        return true;
    }
    if (req_type == REQ_GET_TELEMETRY) {
        // Reply = [their_ts(4)][CayenneLPP]. LPP (electroniccats/CayenneLPP 1.6.1):
        //   voltage point:    [ch=1][0x74][int16_be(mV/10)]  (0.01 V, signed)
        //   temperature point: [ch=1][0x67][int16_be(C*10)]   (0.1  C, signed)
        // Channel 1 = TELEM_CHANNEL_SELF. Both are 'base' telemetry → guest-readable,
        // matching the official firmware (which adds voltage + MCU temp on channel 1).
        int16_t batt_mv = (int16_t)measure_battery_mv();
        int16_t temp_c  = (int16_t)measure_mcu_temp();
        static uint8_t lpp[8];
        int p = 0;
        int16_t vraw = batt_mv / 10;        // volts*100 == mV/10
        lpp[p++] = 1;                        // TELEM_CHANNEL_SELF
        lpp[p++] = 0x74;                     // LPP_VOLTAGE
        lpp[p++] = (uint8_t)((vraw >> 8) & 0xFF);
        lpp[p++] = (uint8_t)(vraw & 0xFF);
        if (temp_c > -127) {                 // skip the point if the sensor failed
            int16_t traw = temp_c * 10;      // C*10
            lpp[p++] = 1;
            lpp[p++] = 0x67;                 // LPP_TEMPERATURE
            lpp[p++] = (uint8_t)((traw >> 8) & 0xFF);
            lpp[p++] = (uint8_t)(traw & 0xFF);
        }
        memcpy(resp, data, 4);               // reflect the request ts as the tag
        memcpy(resp + 4, lpp, p);
        admin_reply(e, PAYLOAD_TYPE_RESPONSE, resp, 4 + p, rx_ctx.flood, SERVER_RESPONSE_DELAY);
        e->last_activity_ms = millis();
        e->last_ts = their_ts;
        return true;
    }
    // Unknown request type: log + dump the request fields, no reply.
    slog("REQ unhandled type=0x%02X", req_type);
#ifdef SP_DUMP_PAYLOAD    
    hex_dump(data + 4, len - 4, 24);
#endif    
    return true;
}

// TXT_MSG: payload = [dest_hash][src_hash][MAC+AES(ts(4)+flags(1)+text)]
// Returns true if a session decrypted it (ours), false → caller relays it.
static bool handle_txt_msg(const uint8_t* pl, int plen) {
    if (plen < 2 + 2 + 5) { slog("TXM short"); return false; }
    uint8_t src_hash = pl[1];
    // The sender sizes the datagram to exactly 5+text_len and omits the null
    // terminator; when 5+text_len is a 16-multiple there is no zero padding.
    // admin_decrypt() NUL-terminates right after the plaintext.
    int len = 0;
    AclEntry* e = session_decrypt(src_hash, pl + 2, plen - 2, &len);
    if (!e) { slog("TXM no sess/MAC"); return false; }
    if (len < 5) return true;
    uint8_t* data = dec_buf;
    uint32_t their_ts; memcpy(&their_ts, data, 4);
    // Replay guard (official): older → drop; equal → a retry of the last command,
    // don't run it again (a replayed 'erase' must not re-execute).
    if (their_ts <= e->last_ts) { slog("TXM replay/retry"); return true; }
    uint8_t flags = data[4] >> 2;
    const char* text = (const char*)(data + 5);

    // Verbose (USB only): hex dump of the FULL decrypted command text, to expose
    // multi-var / multi-get batches and any non-printable separators.
    if (rx_ring_log_enabled()) {
        int tl = (int)strnlen(text, 150);
        if (tl > 64) tl = 64;
        dlog("TXM dec=%d txtlen=%d hex:", len, tl);
        for (int off = 0; off < tl; off += 20) {
            static char hb[48];
            int n = snprintf(hb, sizeof(hb), "  %02d:", off);
            int cnt = (tl - off > 20) ? 20 : (tl - off);
            for (int i = 0; i < cnt && n < 46; i++)
                n += snprintf(hb + n, sizeof(hb) - n, "%02X", (unsigned)data[5 + off + i]);
            Serial1.println(hb);
        }
    }

    // The app prefixes commands with a short transaction ID ("<sess>|") so it
    // can match each reply to the request that produced it. Strip it, run the
    // command, and echo it back in the reply ("<sess>|<reply>"). No '|', or a
    // run of >8 chars before it, is treated as a plain (unprefixed) command.
    static char sess[16];
    int sess_len = 0;
    const char* cmd = text;
    {
        const char* p = strchr(text, '|');
        if (p && (int)(p - text) >= 1 && (int)(p - text) <= 8) {
            sess_len = (int)(p - text);
            memcpy(sess, text, sess_len);
            sess[sess_len] = '\0';
            cmd = p + 1;
        }
    }
    dlog("TXM src=%02X fl=%d cmd='%s'", src_hash, flags, cmd);

    // The app sends commands as TXT_TYPE_CLI_DATA (1) or TXT_TYPE_CLI_COMMAND (3);
    // both mean "run this". Genuine command *replies* are addressed to the client,
    // never to us, so accepting both can't mis-fire here.
    if (flags != TXT_TYPE_CLI_COMMAND && flags != TXT_TYPE_CLI_DATA) {
        slog("TXM not cmd"); return true;
    }
    e->last_ts = their_ts;   // consumed (even if denied) so it can't be replayed
    if (e->perms < cmd_perm_needed(cmd)) { slog("TXM deny"); return true; }

    static char reply[176];
    int rlen = cli_execute(cmd, reply, sizeof(reply), their_ts);
    int prefix_len = sess_len ? (sess_len + 1) : 0;   // "<sess>|"
    if (rlen > 171 - prefix_len) rlen = 171 - prefix_len;   // keep ts(4)+flags(1)+text ≤ 176

    // reply as TXT_MSG CLI_DATA: [ts(4)][flags=CLI_DATA<<2][<sess>|]<reply>
    static uint8_t out[180];
    uint32_t now = now_epoch();
    if (now == their_ts) now++;   // official workaround: reply ts must differ from the request's
    memcpy(out, &now, 4);
    out[4] = (uint8_t)(TXT_TYPE_CLI_DATA << 2);
    int o = 5;
    if (prefix_len) { memcpy(out + o, sess, sess_len); out[o + sess_len] = '|'; o += prefix_len; }
    memcpy(out + o, reply, rlen);
    dlog("TXM reply %d bytes", rlen);
    // Official: CLI replies go DIRECT if out_path is known, else flood (no PATH return).
    admin_reply(e, PAYLOAD_TYPE_TXT_MSG, out, o + rlen, false, CLI_REPLY_DELAY_MILLIS);

    e->last_activity_ms = millis();
    return true;
}

// PATH (0x08) to us: payload = [dest][src][MAC+AES(path_len(1) path extra_type extra)].
// The client's reciprocal path after our PATH return: store it as out_path so
// replies go DIRECT (official onPeerPathRecv). Returns true if a session
// decrypted it (ours), false → relay.
static bool handle_path(const uint8_t* pl, int plen) {
    if (plen < 2 + 2 + 16) return false;
    int len = 0;
    AclEntry* e = session_decrypt(pl[1], pl + 2, plen - 2, &len);
    if (!e) return false;
    uint8_t ph = dec_buf[0];
    int hs = ((ph >> 6) & 0x03) + 1, pb = (ph & 0x3F) * hs;
    if (hs == 4 || pb > MAX_PATH_SIZE || 1 + pb > len) return true;   // bad encoding
    memcpy(e->out_path, dec_buf + 1, pb);
    e->out_path_len = ph;
    e->last_activity_ms = millis();
    dlog("PATH from %02X: %d hops", e->pub[0], ph & 0x3F);
    return true;
}

// True if our full hash (own_pubkey[0..hash_size-1]) appears anywhere in the
// path. Compares all hash_size bytes per hop — not just the first — so a
// 2/3-byte path can't false-positive on a first-byte collision with another
// node (matches the official's full-hash loop check).
static bool path_contains_own(const uint8_t* path, int hops, uint8_t hash_size) {
    for (int j = 0; j < hops; j++) {
        const uint8_t* e = path + (size_t)j * hash_size;
        bool m = true;
        for (int k = 0; k < hash_size; k++)
            if (e[k] != own_pubkey[k]) { m = false; break; }
        if (m) return true;
    }
    return false;
}

// ─── Node discovery (official CONTROL packets, zero-hop only) ────────────────
// discover.neighbors sends one small NODE_DISCOVER_REQ; repeaters in range answer
// with NODE_DISCOVER_RESP (tag + pubkey) and land in the neighbours list. We also
// answer other nodes' requests, rate-limited like the official (4 per 2 min).
#define PAYLOAD_TYPE_CONTROL        0x0B
#define CTL_TYPE_NODE_DISCOVER_REQ  0x80
#define CTL_TYPE_NODE_DISCOVER_RESP 0x90
static uint32_t discover_tag = 0, discover_until_ms = 0;
static uint32_t disc_win_s = 0;
static uint8_t  disc_count = 0;

static void send_zero_hop_control(const uint8_t* data, int len, uint32_t delay_ms) {
    uint8_t b[2 + 6 + 32];
    b[0] = (uint8_t)(ROUTE_DIRECT | (PAYLOAD_TYPE_CONTROL << 2));
    b[1] = 0;                                   // zero hop
    memcpy(b + 2, data, len);
    dedup_seen(b + 2, PAYLOAD_TYPE_CONTROL, (uint8_t)len);
    tx_enqueue(b, 2 + len, 0, delay_ms);
}

void cli_discover_neighbors(void) {
    uint8_t d[10];
    d[0] = CTL_TYPE_NODE_DISCOVER_REQ;          // prefix_only = 0
    d[1] = 1 << ADV_TYPE_REPEATER;              // filter: repeaters
    discover_tag = rng_next();
    memcpy(d + 2, &discover_tag, 4);
    memset(d + 6, 0, 4);                        // since = 0
    discover_until_ms = millis() + 60000UL;
    send_zero_hop_control(d, sizeof(d), 0);
    slog("discover sent");
}

static void on_control(const uint8_t* pl, int plen, int8_t snr_x4) {
    uint8_t type = pl[0] & 0xF0;
    if (type == CTL_TYPE_NODE_DISCOVER_REQ && plen >= 6 && cfg.repeat_en
        && (pl[1] & (1 << ADV_TYPE_REPEATER))) {
        uint32_t now_s = uptime_secs();
        if (now_s - disc_win_s >= 120) { disc_win_s = now_s; disc_count = 0; }
        if (disc_count >= 4) return;            // rate limit
        disc_count++;
        // ponytail: the optional 'since' filter is ignored (we always answer); add a
        // config-modified timestamp if clients start relying on it.
        uint8_t r[6 + 32];
        r[0] = CTL_TYPE_NODE_DISCOVER_RESP | ADV_TYPE_REPEATER;
        r[1] = (uint8_t)snr_x4;                 // inbound SNR, for the requester
        memcpy(r + 2, pl + 2, 4);               // their tag
        memcpy(r + 6, own_pubkey, 32);
        int rlen = (pl[0] & 1) ? 6 + 8 : 6 + 32;   // prefix_only
        // official: retransmit delay x4, as many nodes answer at once
        send_zero_hop_control(r, rlen, retransmit_delay(2 + rlen, cfg.txdelay_x10) * 4);
    } else if (type == CTL_TYPE_NODE_DISCOVER_RESP && plen >= 6 + 32
               && (pl[0] & 0x0F) == ADV_TYPE_REPEATER && discover_tag
               && (int32_t)(millis() - discover_until_ms) < 0
               && memcmp(pl + 2, &discover_tag, 4) == 0
               && memcmp(pl + 6, own_pubkey, 32) != 0) {
        neighbor_add(pl + 6, uptime_secs(), snr_x4);
    }
}

static bool process_pkt(const uint8_t* data, int len) {
    relay_delay_x10 = 0;   // set on every relay return
    relay_pri       = 0;
    if (len < 1) { dlog("Drop: malformed"); return false; }

    // Layout: header [transport codes(4), route types 0/3 only] path_hdr path payload
    uint8_t header = data[0];
    uint8_t route  = header & 0x03;
    bool    direct = (route == ROUTE_DIRECT || route == ROUTE_TRANSPORT_DIRECT);
    uint8_t ptype  = (header >> 2) & 0x0F;
    int     ph     = path_hdr_offset(header);
    if (len < ph + 2) { dlog("Drop: malformed"); return false; }

    // Path header byte: [hash_size_code(2) | hop_count(6)]
    uint8_t path_hdr  = data[ph];
    uint8_t hop_count = path_hdr & 0x3F;
    uint8_t hs_code   = (path_hdr >> 6) & 0x03;
    uint8_t hash_size = hs_code + 1;
    int     path_bytes = hop_count * hash_size;
    // Official Packet::isValidPathLen: code 3 (4-byte hashes) is reserved, path <= 64 B
    if (hs_code == 3 || path_bytes > MAX_PATH_SIZE) { dlog("Drop: bad path"); return false; }
    int idx = ph + 1;
    if (idx + path_bytes >= len) { dlog("Drop: malformed"); return false; }   // need >= 1 payload byte

    const uint8_t* path_ptr    = data + idx;
    const uint8_t* payload_ptr = data + idx + path_bytes;
    int            payload_len = len - idx - path_bytes;
    if (payload_len > MAX_PAYLOAD) { dlog("Drop: too large"); return false; }   // official drops these

    // RX log (RX/TX correlation): ptype, first 2 payload bytes (dest/src for
    // admin, pubkey for advert), hop count, fingerprint. If this fp matches a
    // recent TX fp, our own packet is coming back (self-pickup or a peer echo).
    if (payload_len >= 2 && rx_ring_log_enabled()) {
        char fp[9];
        short_fp(payload_ptr, ptype, (uint8_t)payload_len, fp);
        dlog("RX p=%d d=%02X s=%02X hc=%d fp=%s", ptype, payload_ptr[0], payload_ptr[1], (int)hop_count, fp);
    }

    // ── Neighbours: zero-hop adverts from other REPEATERS only ───────────────
    // (official putNeighbour). The appdata flags byte follows
    // pubkey(32) + timestamp(4) + signature(64). Time stored = when WE heard it.
    if (ptype == PAYLOAD_ADVERT && hop_count == 0 && payload_len > 100
        && (payload_ptr[100] & 0x0F) == ADV_TYPE_REPEATER
        && memcmp(payload_ptr, own_pubkey, 32) != 0) {
        neighbor_add(payload_ptr, uptime_secs(), (int8_t)(radio.getSNR() * 4.0f));
    }

    // ── CONTROL (direct, payload[0] bit 7): zero-hop only, never relayed ───
    if (direct && ptype == PAYLOAD_TYPE_CONTROL && (payload_ptr[0] & 0x80)) {
        if (hop_count == 0) on_control(payload_ptr, payload_len, (int8_t)(radio.getSNR() * 4.0f));
        return false;
    }

    // ── TRACE (direct): payload = tag(4) auth(4) flags(1) hashes[...] ────────
    // The path field collects one SNR byte per hop so far. Forward if the hash
    // at position <hops so far> is ours, appending our SNR (official Mesh.cpp).
    if (direct && ptype == PAYLOAD_TYPE_TRACE) {
        if (!cfg.repeat_en || payload_len < 9 || hs_code != 0 || hop_count >= 63) return false;
        uint8_t path_sz = payload_ptr[8] & 0x03;     // trace hash size = 1 << path_sz
        int hsz        = 1 << path_sz;
        int hashes_len = payload_len - 9;
        int offset     = hop_count << path_sz;
        if (offset + hsz > hashes_len) return false;                    // end of trace (not for a repeater)
        if (memcmp(payload_ptr + 9 + offset, own_pubkey, hsz) != 0) return false;   // not our turn
        if (dedup_seen(payload_ptr, ptype, (uint8_t)payload_len, hop_count)) {
            stat_direct_dups++; dlog("Drop dedup"); return false;
        }
        if (len + 1 > 255) return false;
        memcpy(relay_buf, data, ph);                 // header (+ transport codes)
        relay_len = ph;
        relay_buf[relay_len++] = (uint8_t)(hop_count + 1);
        memcpy(relay_buf + relay_len, path_ptr, hop_count); relay_len += hop_count;
        relay_buf[relay_len++] = (uint8_t)(int8_t)(radio.getSNR() * 4.0f);
        memcpy(relay_buf + relay_len, payload_ptr, payload_len); relay_len += payload_len;
        uint32_t tag; memcpy(&tag, payload_ptr, 4);
        slog("Trace %08lX hop %u", (unsigned long)tag, (unsigned)(hop_count + 1));
        relay_delay_x10 = cfg.direct_txdelay_x10;
        relay_pri       = 5;
        return true;
    }

    // ── Mesh-admin packets addressed to us (dest_hash == own_hash) ──────────
    // Only when we are the final recipient: any flood, or a direct packet whose
    // path is used up (a direct packet still carrying hops belongs to them).
    bool seen = false;   // already run through dedup_seen below
    if ((ptype == PAYLOAD_TYPE_ANON_REQ || ptype == PAYLOAD_TYPE_TXT_MSG ||
         ptype == PAYLOAD_TYPE_RESPONSE || ptype == PAYLOAD_TYPE_REQ ||
         ptype == PAYLOAD_TYPE_PATH)
        && payload_len >= 2 && payload_ptr[0] == own_hash && (!direct || hop_count == 0)) {
        dlog("ADM p=%d dst=%02X src=%02X hc=%d", ptype, payload_ptr[0], payload_ptr[1], (int)hop_count);
        // Dedup first: a re-relayed copy of a command looping back through
        // another repeater must not be reprocessed (duplicate replies).
        if (dedup_seen(payload_ptr, ptype, (uint8_t)payload_len)) {
            dlog("Drop dedup");
            return false;
        }
        seen = true;
        rx_ctx.flood    = !direct;            // decides how the reply is routed
        rx_ctx.path_hdr = path_hdr;
        rx_ctx.path     = path_ptr;
        bool ours = false;
        if      (ptype == PAYLOAD_TYPE_ANON_REQ) ours = handle_anon_req(payload_ptr, payload_len);
        else if (ptype == PAYLOAD_TYPE_PATH)     ours = handle_path(payload_ptr, payload_len);
        else if (ptype == PAYLOAD_TYPE_TXT_MSG)  ours = handle_txt_msg(payload_ptr, payload_len);
        else if (ptype == PAYLOAD_TYPE_REQ)      ours = handle_req(payload_ptr, payload_len);
        if (ours) return false;   // for us: never relayed
        // Not decryptable: it's for another node sharing our 1-byte hash —
        // relay it like any other packet (official routeRecvPacket).
    }

    // ── DIRECT routing ────────────────────────────────────────────────────────
    // Forward only if we are the NEXT hop (first path hash), with ourselves
    // removed from the front of the path (official removeSelfFromPath).
    if (direct) {
        if (hop_count == 0) return false;   // zero-hop: for neighbours only, never relayed
        if (!cfg.repeat_en) { dlog("Drop: repeat off"); return false; }
        if (memcmp(path_ptr, own_pubkey, hash_size) != 0) return false;   // not our hop
        if (dedup_seen(payload_ptr, ptype, (uint8_t)payload_len)) {
            stat_direct_dups++;
            dlog("Drop dedup");
            return false;
        }
        memcpy(relay_buf, data, ph);                 // header (+ transport codes)
        relay_len = ph;
        relay_buf[relay_len++] = (uint8_t)((hop_count - 1) | (hs_code << 6));
        memcpy(relay_buf + relay_len, path_ptr + hash_size, path_bytes - hash_size);
        relay_len += path_bytes - hash_size;
        memcpy(relay_buf + relay_len, payload_ptr, payload_len);
        relay_len += payload_len;
        dlog("Relay direct");
        relay_delay_x10 = cfg.direct_txdelay_x10;
        relay_pri       = 0;   // routed traffic: highest priority (official)
        return true;
    }

    // ── FLOOD routing (ROUTE_FLOOD 0x01 + ROUTE_TRANSPORT_FLOOD 0x00) ────────

    // Guard: relay disabled via CLI (`set repeat off`)
    if (!cfg.repeat_en) { dlog("Drop: repeat off"); return false; }

    // Guard: max hops, and room to append our hash (path <= 64 B, count <= 63)
    if (hop_count >= (cfg.flood_max ? cfg.flood_max : MAX_HOPS) || hop_count >= 63
        || path_bytes + hash_size > MAX_PATH_SIZE) {
        dlog("Drop: max hops"); return false;
    }

    // Dedup check
    if (!seen && dedup_seen(payload_ptr, ptype, (uint8_t)payload_len)) {
        stat_flood_dups++;
        dlog("Drop dedup");
#ifdef SP_DUMP_PAYLOAD
        hex_dump(payload_ptr, payload_len, 24);
#endif
        return false;
    }

    // Loop detection (off = skip; minimal/moderate/strict all drop when our
    // full hash appears in the path — compared across all hash_size bytes so
    // multi-byte paths don't false-positive on a first-byte collision)
    if ((cfg.loop_detect & 0x03) != 0 && path_contains_own(path_ptr, hop_count, hash_size)) {
        dlog("Drop loop");
#ifdef SP_DUMP_PAYLOAD
        hex_dump(payload_ptr, payload_len, 24);
#endif
        return false;
    }

    // Build relay packet: header (+ transport codes), hop_count+1, path + own hash, payload
    if (len + hash_size > 255) { dlog("Drop too large"); return false; }
    memcpy(relay_buf, data, ph);
    relay_len = ph;
    uint8_t new_hop = hop_count + 1;
    relay_buf[relay_len++] = (uint8_t)(new_hop | (hs_code << 6));
    memcpy(relay_buf + relay_len, path_ptr, path_bytes);
    relay_len += path_bytes;
    memcpy(relay_buf + relay_len, own_pubkey, hash_size);   // own hash (1..3 bytes)
    relay_len += hash_size;
    memcpy(relay_buf + relay_len, payload_ptr, payload_len);
    relay_len += payload_len;

    dlog("Relay hop=%u", (unsigned)new_hop);
    relay_delay_x10 = cfg.txdelay_x10;   // flood relay → txdelay backoff
    relay_pri       = new_hop;           // closer sources first (official)
    return true;
}

// ─── Stats CLI: official StatsFormatHelper JSON (parsed by the official tools) ─
void format_stats_core(char* b, int n) {
    snprintf(b, n, "{\"battery_mv\":%u,\"uptime_secs\":%lu,\"errors\":%u,\"queue_len\":%u}",
             (unsigned)measure_battery_mv(), (unsigned long)uptime_secs(),
             (unsigned)err_flags, (unsigned)txq_count());
}
void format_stats_radio(char* b, int n) {
    int x = stat_last_snr_x4;                    // SNR x4 → "%.2f" without float printf
    unsigned a = (unsigned)(x < 0 ? -x : x);
    snprintf(b, n, "{\"noise_floor\":%d,\"last_rssi\":%d,\"last_snr\":%s%u.%02u,"
                   "\"tx_air_secs\":%lu,\"rx_air_secs\":%lu}",
             (int)stat_noise_floor, (int)stat_last_rssi, x < 0 ? "-" : "", a / 4, (a % 4) * 25,
             (unsigned long)(stat_tx_air_ms / 1000), (unsigned long)(stat_rx_air_ms / 1000));
}
void format_stats_packets(char* b, int n) {
    snprintf(b, n, "{\"recv\":%lu,\"sent\":%lu,\"flood_tx\":%lu,\"direct_tx\":%lu,"
                   "\"flood_rx\":%lu,\"direct_rx\":%lu,\"recv_errors\":%lu}",
             (unsigned long)stat_rx, (unsigned long)(stat_sent_flood + stat_sent_direct),
             (unsigned long)stat_sent_flood, (unsigned long)stat_sent_direct,
             (unsigned long)stat_recv_flood, (unsigned long)stat_recv_direct,
             (unsigned long)stat_recv_errors);
}

// ─── System Clock Configuration (8 MHz HSI, PLL OFF) ──────────────────────
// Overrides the framework's WEAK SystemClock_Config (which ran at 64 MHz via PLL).
// Running directly on 8 MHz HSI with the PLL disabled cuts STM32 Sleep mode current
// from ~12 mA down to ~1.5-2 mA.
extern "C" void SystemClock_Config(void) {
    RCC_OscInitTypeDef RCC_OscInitStruct = {};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {};

    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState = RCC_HSI_ON;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_OFF;
    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
        while (1);
    }

    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK
                                | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK) {
        while (1);
    }
}

// ─── Peripheral power management ───────────────────────────────────────────
// Gate clock to unused peripherals and power-down ADC converters initialized by
// Arduino core defaults, saving unnecessary idle current.
static void peripherals_disable_unused(void) {
    // 1. Power down and gate off ADCs if active
#if defined(ADC1)
    if (ADC1->CR2 & ADC_CR2_ADON) {
        ADC1->CR2 &= ~ADC_CR2_ADON;
    }
    __HAL_RCC_ADC1_CLK_DISABLE();
#endif
#if defined(ADC2)
    if (ADC2->CR2 & ADC_CR2_ADON) {
        ADC2->CR2 &= ~ADC_CR2_ADON;
    }
    __HAL_RCC_ADC2_CLK_DISABLE();
#endif

    // 2. Disable unused APB1 peripheral clocks
#if defined(__HAL_RCC_TIM2_CLK_DISABLE)
    __HAL_RCC_TIM2_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_TIM3_CLK_DISABLE)
    __HAL_RCC_TIM3_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_TIM4_CLK_DISABLE)
    __HAL_RCC_TIM4_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_SPI2_CLK_DISABLE)
    __HAL_RCC_SPI2_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_USART2_CLK_DISABLE)
    __HAL_RCC_USART2_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_USART3_CLK_DISABLE)
    __HAL_RCC_USART3_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_I2C1_CLK_DISABLE)
    __HAL_RCC_I2C1_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_I2C2_CLK_DISABLE)
    __HAL_RCC_I2C2_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_USB_CLK_DISABLE)
    __HAL_RCC_USB_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_CAN1_CLK_DISABLE)
    __HAL_RCC_CAN1_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_WWDG_CLK_DISABLE)
    __HAL_RCC_WWDG_CLK_DISABLE();
#endif

    // 3. Disable unused APB2 peripheral clocks (TIM1, GPIOD)
#if defined(__HAL_RCC_TIM1_CLK_DISABLE)
    __HAL_RCC_TIM1_CLK_DISABLE();
#endif
#if defined(__HAL_RCC_GPIOD_CLK_DISABLE)
    __HAL_RCC_GPIOD_CLK_DISABLE();
#endif
}

// ─── ARDUINO ENTRY POINTS ───────────────────────────────────────────────────

void setup(void) {
    // LED
    pinMode(PIN_LED,  OUTPUT);
    // Boot signature: 5 quick flashes so a successful *app* boot is easy to tell
    // apart from the ROM bootloader (which shows a SOLID LED). Fires before radio
    // init, so you get it even if the radio later comes up in degraded mode.
    led_blink(5, 50);
    digitalWrite(PIN_LED, LED_OFF);

    // RF switch pins
    pinMode(PIN_TXEN, OUTPUT); digitalWrite(PIN_TXEN, LOW);
    pinMode(PIN_RXEN, OUTPUT); digitalWrite(PIN_RXEN, LOW);

    // Serial1 = USART1 = PA9(TX)/PA10(RX) = CH340 USB
    Serial1.begin(115200);
    delay(200);
    // Log the reset reason (RCC->CSR latches how the previous boot ended).
    // IWDG = watchdog starvation (loop blocked > 8 s); LP = STOP/standby exit
    // path misbehaving; PIN/POR = hardware/power; SW = our own reboot().
    {
        uint32_t r = RCC->CSR;
        Serial1.print("RESET:");
        if (r & RCC_CSR_LPWRRSTF) Serial1.print(" STOP/LP");
        if (r & RCC_CSR_WWDGRSTF) Serial1.print(" WWDG");
        if (r & RCC_CSR_IWDGRSTF) Serial1.print(" IWDG");
        if (r & RCC_CSR_SFTRSTF)  Serial1.print(" SW");
        if (r & RCC_CSR_PORRSTF)  Serial1.print(" POR");
        if (r & RCC_CSR_PINRSTF)  Serial1.print(" PIN");
        Serial1.println();
    }
    IWatchdog.begin(8000000);  // 8 s IWDG — auto-resets if radio HALT or loop freeze

    // Disable unused MCU peripherals to save power
    peripherals_disable_unused();

    // ── Configuration: build-flag defaults ← flash prefs overlay ──────────────
    prefs_load();
    cli_begin();

    // Clock: build time, or the backed-up clock if a reset (not power loss)
    // happened after a later time was known (+1 s so timestamps never repeat).
    ts_base = build_unix_ts();
    {
        uint32_t saved = bkp_restore_time();
        if (saved >= ts_base) ts_base = saved + 1;
    }
    identity_init();
    rng_seed_uid();   // per-chip retransmit-delay RNG (see retransmit_delay)
    Serial1.println();
    Serial1.print("=== SPECTER MeshCore Repeater v");
    Serial1.print(FW_VERSION);
    Serial1.print(" [");
    Serial1.print(cfg.name);
    Serial1.println("] ===");
    Serial1.print("Hash: 0x"); Serial1.println(own_hash, HEX);

    Serial1.print("Radio init...");
    if (radio_init()) {
        radio_ok = true;
        // Start the duty-cycle budget full (as the official Dispatcher does)
        last_budget_update = millis();
        tx_budget_ms = (cfg.dutycycle > 0 && cfg.dutycycle < 100) ?
            (uint32_t)(((uint64_t)DUTY_WINDOW_MS * cfg.dutycycle) / 100) : DUTY_WINDOW_MS;
        Serial1.println(" OK");
        digitalWrite(PIN_LED, LED_OFF);   // OFF, ready
    } else {
        radio_ok = false;
        // Do NOT halt: a bad radio setting (or a transient RF fault) must not
        // brick the serial CLI. Stay in degraded mode — loop() keeps polling
        // the CLI and retries radio_init() until the settings become valid.
        Serial1.println(" FAILED - degraded mode, CLI alive, retrying");
        slog("RADIO init FAILED: degraded mode (fix via CLI, e.g. 'set radio')");
        digitalWrite(PIN_LED, LED_ON);    // solid on = radio not ready
    }
}

static uint32_t last_local_advert = 0;
static uint32_t last_flood_advert = 0;
static bool     first_advert      = false;
static uint32_t last_beat_ms      = 0;   // LED heartbeat (10 s)
static uint32_t last_alive_ms     = 0;   // ALIVE log line (60 s)
static bool     advert_pending    = false;      // CLI-triggered advert
static bool     advert_zerohop    = false;
static bool     led_pulse_on      = false;      // non-blocking LED pulse in progress
static uint32_t led_off_at        = 0;

// Non-blocking LED pulse (the old led_blink() busy-waited in delay() with the
// radio deaf). Turned off by loop(); TX keeps the LED on while transmitting.
static void led_pulse(uint16_t ms) {
    digitalWrite(PIN_LED, LED_ON);
    led_off_at   = millis() + ms;
    led_pulse_on = true;
}

// ─── Console log ring (declared in config.h, implemented in cli.cpp) ─────────
// All runtime diagnostics go here instead of straight to serial; the user
// reads them on demand with the `log` command.
// ─── CLI hooks (declared in config.h, used by cli.cpp) ───────────────────────
void cli_reboot(void) { NVIC_SystemReset(); }
void cli_set_rxgain(bool boosted) { radio.setRxBoostedGainMode(boosted); }

// ─── Programmatic bootloader entry (serial "DFU") ────────────────────────────
// The STM32F103 has no USB DFU. If the board's BOOT0 and RESET lines are
// accessible as GPIOs, define them in platformio.ini:
//   -D DFU_BOOT0_PIN=PB12
//   -D DFU_RST_PIN=PB13
// then `dfu` over the CLI pulls BOOT0 high, pulses RESET low for 100 ms and
// lets go → the MCU reboots into the UART bootloader
// ready for `stm32flash -w firmware.bin -v -R -b 115200 <port>`.
#ifdef DFU_BOOT0_PIN
void cli_dfu(void) {
    pinMode(DFU_BOOT0_PIN, OUTPUT);
    pinMode(PIN_NRST,   OUTPUT);
    digitalWrite(PIN_NRST, HIGH);    // ensure not held in reset
    delay(20);
    IWatchdog.set(IWDG_TIMEOUT_MAX); // watchdog won't interrupt our "DFU"
    Serial1.println("Entering bootloader...");
    Serial1.println("Close the Serial monitor and wait ~25s before upload");
    delay(500);                         // let the reply drain through CH340
    Serial1.write(0x04);                // EOF/EOT: some terminal tools close on this
    delay(500);
    digitalWrite(DFU_BOOT0_PIN, HIGH);  // BOOT0=1 on the reset edge
    delay(20);
    digitalWrite(PIN_NRST, LOW);     // pulse NRST
    
    while (true) { delay(10); }         // (unreachable; bootloader takes over)
}
#endif

uint32_t cli_now_epoch(void) { return now_epoch(); }

void cli_set_time(uint32_t epoch) {
    ts_base = epoch - uptime_secs();
    bkp_save_time(epoch);
}

const char* cli_version_str(void) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "%s (%s)", FW_VERSION, __DATE__);
    return buf;
}

void cli_send_advert_now(bool zero_hop) {
    advert_pending = true;
    advert_zerohop = zero_hop;
}

// Build, sign and queue our advert. zero_hop → neighbours only (not relayed).
// Official priorities: zero-hop 0, flood advert 3 (de-prioritised).
static void send_advert(bool zero_hop, const char* why, uint32_t delay_ms) {
    uint8_t abuf[MAX_PKT];
    int     alen = build_advert(abuf, zero_hop);
    slog("ADVERT %s", why);
    tx_enqueue(abuf, alen, zero_hop ? 0 : 3, delay_ms);
}

// ─── STOP Mode Manager ──────────────────────────────────────────────────────
void loop(void) {
    IWatchdog.reload();
    uint32_t now = millis();
    uptime_secs();   // tick the 64-bit uptime accumulator (must run < every 49 days)

    // ── CLI (USB serial) ─────────────────────────────────────────────────────
    cli_poll();   // ALWAYS polled, even in degraded mode, so serial is never bricked

    // ── Radio not ready: retry init periodically, do no radio work ──────────────
    if (!radio_ok) {
        if (now - last_radio_retry >= 3000UL) {
            last_radio_retry = now;
            if (radio_init()) {
                radio_ok     = true;
                rx_started   = false;
                first_advert = false;   // re-send the initial advert once up
                slog("RADIO up after retry");
                digitalWrite(PIN_LED, LED_OFF);
            } else {
                led_blink(3, 120);      // triple-blink = radio still down
            }
        }
        return;
    }

    // ── LED: heartbeat every 10 s + end of a pulse (non-blocking) ────────────
    if (now - last_beat_ms >= 10000UL) {
        last_beat_ms = now;
        led_pulse(50);
    }
    if (led_pulse_on && !tx_active && (int32_t)(now - led_off_at) >= 0) {
        digitalWrite(PIN_LED, LED_OFF);
        led_pulse_on = false;
    }
    // ── ALIVE log line every 60 s (keeps the remote log ring uncluttered) ─────
    if (now - last_alive_ms >= 60000UL) {
        last_alive_ms = now;
        bkp_save_time(now_epoch());   // keep the reset-surviving clock fresh
        slog("ALIVE up=%lus rx=%lu relay=%lu drop=%lu",
             (unsigned long)uptime_secs(),
             (unsigned long)stat_rx, (unsigned long)stat_relay, (unsigned long)stat_drop);
    }

    // ── Expire idle mesh-admin sessions (admin.timeout seconds) ──────────────
    {
        static uint32_t last_acl_ms = 0;
        if (adm.admin_timeout > 0 && now - last_acl_ms >= 1000UL) {
            last_acl_ms = now;
            uint32_t lim = (uint32_t)adm.admin_timeout * 1000UL;
            for (int i = 0; i < ACL_MAX; i++) {
                AclEntry* e = (AclEntry*)acl_at(i);
                if (e && e->active && (now - e->last_activity_ms) > lim) {
                    e->active = 0;
                    slog("session %02X expired", e->pub[0]);
                }
            }
        }
    }

    // ── CLI-triggered advert ─────────────────────────────────────────────────
    if (advert_pending) {
        advert_pending = false;
        // official: 1.5 s delay so the CLI reply goes out first
        send_advert(advert_zerohop, advert_zerohop ? "zerohop" : "flood", 1500);
        last_local_advert = now;   // don't double-send right after
    }

    // ── ADVERT timers (intervals from cfg, MeshCore standard) ────────────────
    uint32_t local_iv  = (uint32_t)cfg.zerohop_adv_min * 60UL * 1000UL;  // 0 = off
    uint32_t flood_iv  = (uint32_t)cfg.flood_advert_h * 3600UL * 1000UL;

    bool do_advert = false;
    bool advert_zero = false;
    const char* advert_type = "";

    // First ADVERT at boot (flood)
    if (!first_advert && now >= FIRST_ADVERT_MS) {
        do_advert    = true;
        first_advert = true;
        last_flood_advert = now;
        last_local_advert = now;
        advert_type = "initial";
    }
    // Flood ADVERT every N hours (global presence)
    else if (first_advert && (now - last_flood_advert) >= flood_iv) {
        do_advert = true;
        last_flood_advert = now;
        last_local_advert = now;  // sync both timers
        advert_type = "flood";
    }
    // Local (zero-hop) ADVERT every N minutes (neighbor discovery)
    else if (first_advert && local_iv > 0 &&
             (now - last_local_advert) >= local_iv) {
        do_advert = true;
        last_local_advert = now;
        advert_zero = true;          // periodic local advert = zero-hop
        advert_type = "local";
    }

    if (do_advert) send_advert(advert_zero, advert_type, 0);

    // ── Radio: TX in flight → wait for TxDone; else receive + send ──────────
    // DIO1 (PC15) wakes the CPU from __WFI() on RxDone / TxDone (dio1_flag).
    // While a packet waits in the queue the radio stays in RX — nothing here
    // blocks, so the CPU sleeps between SysTick ticks.
    if (tx_active) check_tx_done(now);

    if (!tx_active) {
        if (!rx_started) {
            // Continuous RX; PREAMBLE_DETECTED latched in the IRQ status (not on
            // DIO1, so no extra wake-ups) for listen-before-talk — official
            // CustomSX1262::startReceive.
            int err = radio.startReceive(RADIOLIB_SX126X_RX_TIMEOUT_INF,
                                         RADIOLIB_IRQ_RX_DEFAULT_FLAGS | (1UL << RADIOLIB_IRQ_PREAMBLE_DETECTED),
                                         RADIOLIB_IRQ_RX_DEFAULT_MASK, 0);
            if (err != RADIOLIB_ERR_NONE) {
                err_flags |= ERR_EVENT_STARTRX_TIMEOUT;
                slog("startReceive err: %d", (int)err);
            }
            rx_started = true;
        }

        if (dio1_flag) {
            dio1_flag = false;                    // RxDone
            uint8_t rxbuf[MAX_PKT];
            int state = radio.readData(rxbuf, 0);
            rx_started = false;                   // re-arm (official recvRaw)

            if (state == RADIOLIB_ERR_NONE) {
                int   rxlen = (int)radio.getPacketLength();
                float rssi  = radio.getRSSI();
                float snr   = radio.getSNR();
                rxlog("RX RSSI=%d SNR=%d len=%d", (int)rssi, (int)snr, (int)rxlen);
                stat_last_rssi   = (int16_t)rssi;          // last RX signal level
                stat_last_snr_x4 = (int16_t)(snr * 4.0f);  // last SNR, x4 (keep the fraction)
                stat_rx_air_ms  += toa_ms(rxlen);          // per-packet RX air time
                if (rxlen > 0 && rxlen < MAX_PKT) {
                    stat_rx++;
                    uint8_t route = rxbuf[0] & 0x03;
                    if (route == ROUTE_DIRECT || route == ROUTE_TRANSPORT_DIRECT) stat_recv_direct++;
                    else                                                          stat_recv_flood++;
                    led_pulse(20);                // short pulse = packet received
                    if (process_pkt(rxbuf, rxlen) &&
                        tx_enqueue(relay_buf, relay_len, relay_pri,
                                   retransmit_delay(relay_len, relay_delay_x10))) {
                        stat_relay++;
                    } else {
                        stat_drop++;
                    }
                }
            } else {
                stat_recv_errors++;   // CRC error or other read failure
                slog("readData err: %d", (int)state);
            }
        }

        check_send(now);
    }

    // ── Noise floor sampling (triggered once per 10 minutes) ───────────────────
    // Instead of polling RSSI over SPI continuously every 200 ms, trigger a brief
    // session of N subsequent samples (100 ms apart) once every 10 minutes.
    if (rx_started && !tx_active && !nf_session_active) {
        if (!nf_initial_done && now >= 5000UL) {
            nf_session_active  = true;
            nf_initial_done    = true;
            last_nf_session_ms = now;
            last_nf_sample_ms  = 0;
            nf_samples         = 0;
            nf_sum             = 0;
            nf_attempts        = 0;
        } else if (nf_initial_done && (now - last_nf_session_ms) >= NF_INTERVAL_MS) {
            nf_session_active  = true;
            last_nf_session_ms = now;
            last_nf_sample_ms  = 0;
            nf_samples         = 0;
            nf_sum             = 0;
            nf_attempts        = 0;
        }
    }

    if (nf_session_active && rx_started && !tx_active) {
        if ((now - last_nf_sample_ms) >= NF_BURST_SPACING_MS) {
            last_nf_sample_ms = now;
            nf_attempts++;
            int rssi = (int)radio.getRSSI(false);
            if (stat_noise_floor == 0 || rssi < stat_noise_floor + 14) {
                nf_sum += rssi;
                nf_samples++;
            }
            if (nf_samples >= NF_BURST_SAMPLES || nf_attempts >= NF_MAX_ATTEMPTS) {
                if (nf_samples > 0) {
                    stat_noise_floor = (int16_t)(nf_sum / nf_samples);
                    if (stat_noise_floor < -120) stat_noise_floor = -120;
                } else {
                    // Every sample was > floor + 14 dB: the floor has risen for
                    // good. Reset so the next session reconverges instead of
                    // staying stuck (the official resets its floor similarly).
                    stat_noise_floor = 0;
                }
                nf_session_active = false;
            }
        }
    }

    // Sleep until the next interrupt: SysTick (1 ms, keeps millis() and the
    // timers above running), DIO1 (RxDone/TxDone) or a UART byte.
    __WFI();
}
