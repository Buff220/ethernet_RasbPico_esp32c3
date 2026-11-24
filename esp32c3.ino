// ESP32-C3: WiFi <-> UART SLIP L2 bridge for the Pico usbnet  (v3, self-healing)
// Wiring: ESP GPIO4 (RX) <- Pico GP8 (TX), ESP GPIO5 (TX) -> Pico GP9 (RX), GND common
//
// The ESP joins WiFi using the PC's MAC address (sent by the Pico), then forwards raw Ethernet
// frames between the Pico (SLIP over UART) and the WiFi driver. The ESP itself has no IP traffic.
//
// Control frames (SLIP, ethertype):  Pico->ESP 0x88B5 handshake (host MAC) and 0x88B6 diagnostics,
//                                    ESP->Pico 0x88B7 heartbeat (payload: 1 = WiFi up)
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_private/wifi.h"
#include "esp_system.h"

const char *SSID = "Katv1-5";
const char *PASS = "25022007";

// Lower WiFi TX power = lower current peaks (helps when powered from the Pico's 3V3 pin).
// Raise it (e.g. WIFI_POWER_19_5dBm) if the router is far away.
#define WIFI_TX_POWER WIFI_POWER_15dBm

#define BAUD 1500000
#define RXD 4
#define TXD 5

#define END 0xC0
#define ESC 0xDB
#define ESC_END 0xDC
#define ESC_ESC 0xDD
#define MAXF 1600

SemaphoreHandle_t txMutex;   // slipSend() is used from the WiFi task and from loop()
uint8_t hostMac[6];
volatile bool haveMac = false;
volatile bool wifiUp = false;
uint32_t wifiDownSince = 0;

// debug counters
volatile uint32_t rxBytes = 0;      // raw bytes from the Pico
volatile uint32_t frmFromPico = 0;  // Ethernet frames Pico -> WiFi
volatile uint32_t txFail = 0;       // esp_wifi_internal_tx errors
volatile uint32_t frmToPico = 0;    // Ethernet frames WiFi -> Pico
volatile uint32_t dhcpOut = 0;      // DHCP client packets sent to WiFi (UDP dst port 67)
volatile uint32_t dhcpIn = 0;       // DHCP server packets received from WiFi (UDP src port 67)
volatile uint32_t macMismatch = 0;  // frames from the PC whose source MAC != handshake MAC
volatile uint32_t wifiRxDrops = 0;  // WiFi->Pico frames dropped because the UART was busy
uint32_t reconnects = 0, serialReinits = 0;
volatile uint32_t lastRxMs = 0;     // last time any byte arrived from the Pico
int lastTxErr = 0;
uint32_t picoStats[10] = {0};       // counters reported by the Pico (ethertype 0x88B6)

// SLIP decoder state
static uint8_t slipBuf[MAXF];
static size_t slipN = 0;
static bool slipEsc = false, slipBad = false;

// ---------- SLIP ----------
void slipSend(const uint8_t *d, size_t n) {
  static uint8_t o[2 * MAXF + 4];
  xSemaphoreTake(txMutex, portMAX_DELAY);
  size_t k = 0;
  o[k++] = END;
  for (size_t i = 0; i < n; i++) {
    uint8_t c = d[i];
    if (c == END)      { o[k++] = ESC; o[k++] = ESC_END; }
    else if (c == ESC) { o[k++] = ESC; o[k++] = ESC_ESC; }
    else                 o[k++] = c;
  }
  o[k++] = END;
  // never block the WiFi task: if the UART is backed up, drop the frame (TCP will retransmit)
  if ((size_t)Serial1.availableForWrite() >= k) Serial1.write(o, k);
  else wifiRxDrops++;
  xSemaphoreGive(txMutex);
}

// true if this Ethernet frame is IPv4/UDP and the given port matches the UDP src or dst port
static bool udpPort(const uint8_t *f, size_t len, bool checkDst, uint16_t port) {
  if (len < 14 + 20 + 8 || f[12] != 0x08 || f[13] != 0x00 || f[14 + 9] != 17) return false;
  size_t ihl = (f[14] & 0x0F) * 4;
  if (len < 14 + ihl + 8) return false;
  const uint8_t *u = f + 14 + ihl;
  uint16_t p = checkDst ? ((u[2] << 8) | u[3]) : ((u[0] << 8) | u[1]);
  return p == port;
}

void sendHeartbeat() {
  uint8_t f[15] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0,0,0,0,0,0, 0x88, 0xB7, (uint8_t)(wifiUp ? 1 : 0)};
  slipSend(f, sizeof(f));
}

// ---------- WiFi -> Pico ----------
// Called by the WiFi driver with an already decrypted 802.3 (Ethernet) frame.
esp_err_t wifiRx(void *buf, uint16_t len, void *eb) {
  if (haveMac && len >= 14 && len <= 1514) {
    if (udpPort((const uint8_t *)buf, len, false, 67)) dhcpIn++;
    frmToPico++;
    slipSend((const uint8_t *)buf, len);
  }
  esp_wifi_internal_free_rx_buffer(eb);
  return ESP_OK;
}

// ---------- Pico -> WiFi ----------
void handleFrame(const uint8_t *f, size_t len) {
  // MAC handshake from the Pico: FF:FF:FF:FF:FF:FF / 00:00:00:00:00:00 / 0x88B5 / MAC
  if (len == 20 && f[12] == 0x88 && f[13] == 0xB5) {
    if (!haveMac) {
      memcpy(hostMac, f + 14, 6);
      haveMac = true;
      Serial.printf("\nhost MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                    hostMac[0], hostMac[1], hostMac[2], hostMac[3], hostMac[4], hostMac[5]);
    } else if (memcmp(hostMac, f + 14, 6) != 0) {
      Serial.println("host MAC changed -> restarting to adopt it");
      delay(100);
      ESP.restart();
    }
    return;
  }
  if (len == 14 + 40 && f[12] == 0x88 && f[13] == 0xB6) {   // Pico diagnostics
    memcpy(picoStats, f + 14, sizeof(picoStats));
    return;
  }
  if (!haveMac || len < 14) return;
  if (memcmp(f + 6, hostMac, 6) != 0) macMismatch++;
  if (udpPort(f, len, true, 67)) dhcpOut++;
  frmFromPico++;
  esp_err_t e = esp_wifi_internal_tx(WIFI_IF_STA, (void *)f, (uint16_t)len);
  if (e != ESP_OK) { txFail++; lastTxErr = e; }
}

void slipPoll() {
  while (Serial1.available()) {
    uint8_t c = Serial1.read();
    rxBytes++;
    lastRxMs = millis();
    if (c == END) {
      if (slipN && !slipBad) handleFrame(slipBuf, slipN);
      slipN = 0; slipEsc = false; slipBad = false;
      continue;
    }
    if (slipEsc) { c = (c == ESC_END) ? END : (c == ESC_ESC) ? ESC : c; slipEsc = false; }
    else if (c == ESC) { slipEsc = true; continue; }
    if (slipN < MAXF) slipBuf[slipN++] = c;
    else slipBad = true;               // too long: discard the whole frame
  }
}

void startSerial1() {
  pinMode(RXD, INPUT_PULLUP);          // must be BEFORE Serial1.begin()
  Serial1.setRxBufferSize(8192);       // default is far too small for 1.5 Mbaud
  Serial1.setTxBufferSize(8192);
  Serial1.begin(BAUD, SERIAL_8N1, RXD, TXD);
  slipN = 0; slipEsc = false; slipBad = false;
  lastRxMs = millis();
}

// ---------- WiFi management ----------
static bool isAssociated() {
  wifi_ap_record_t ap;
  return esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
}

void startWifi() {
  WiFi.persistent(false);              // do not wear out flash with credentials
  WiFi.mode(WIFI_STA);
  esp_wifi_set_mac(WIFI_IF_STA, hostMac);   // associate *as the PC*
  WiFi.setAutoReconnect(true);
  // The ESP must not run its own DHCP client / IP traffic: it shares the PC's MAC and would only
  // confuse the router. A link-local static address keeps the ESP's own stack silent.
  WiFi.config(IPAddress(169, 254, 254, 254), IPAddress(169, 254, 254, 253), IPAddress(255, 255, 0, 0));
  WiFi.setSleep(false);                // no WiFi power-save: a bridge must not miss frames
  WiFi.setTxPower(WIFI_TX_POWER);
  WiFi.begin(SSID, PASS);
}

void hardReconnect() {
  Serial.println("\nwifi: full restart of the WiFi driver");
  WiFi.disconnect(true, false);
  delay(300);
  startWifi();
}

const char *resetName(esp_reset_reason_t r) {
  switch (r) {
    case ESP_RST_POWERON:  return "power-on";
    case ESP_RST_SW:       return "software restart";
    case ESP_RST_PANIC:    return "crash/panic";
    case ESP_RST_INT_WDT:  return "interrupt watchdog";
    case ESP_RST_TASK_WDT: return "task watchdog";
    case ESP_RST_WDT:      return "watchdog";
    case ESP_RST_BROWNOUT: return "BROWNOUT (power supply dipped!)";
    default:               return "other";
  }
}

void setup() {
  Serial.begin(115200);
  txMutex = xSemaphoreCreateMutex();
  esp_reset_reason_t rr = esp_reset_reason();
  Serial.printf("\nreset reason: %d (%s)\n", (int)rr, resetName(rr));
  startSerial1();

  // 1) wait for the Pico's MAC handshake (the bridge is useless without it, so wait forever)
  Serial.print("waiting for pico MAC");
  uint32_t lastPrint = 0;
  while (!haveMac) {
    slipPoll(); delay(1);
    if (millis() - lastPrint > 1000) { lastPrint = millis(); Serial.printf(" [rx bytes: %u]", (unsigned)rxBytes); }
    if (millis() - lastRxMs > 10000) { serialReinits++; startSerial1(); }   // Pico silent: re-init the UART
  }
  Serial.println(" ok");

  // 2) associate to WiFi as the PC; keep the Pico informed that we are alive while connecting
  startWifi();
  Serial.print("wifi");
  uint32_t t0 = millis(), lastHb = 0;
  while (!isAssociated()) {
    slipPoll(); delay(10);
    if (millis() - lastHb > 1000) { lastHb = millis(); Serial.print("."); sendHeartbeat(); }
    if (millis() - t0 > 40000) { t0 = millis(); hardReconnect(); }
  }
  wifiUp = true;
  Serial.println();
  Serial.print("bridge mac: "); Serial.println(WiFi.macAddress());
}

void loop() {
  slipPoll();
  uint32_t now = millis();

  // (Re)claim WiFi receive: the ESP's own network stack re-registers itself on every (re)connect,
  // so keep taking it over. Frames then go to wifiRx() instead of the ESP's own TCP/IP stack.
  static uint32_t lastReg = 0;
  if (now - lastReg > 200) {
    lastReg = now;
    esp_wifi_internal_reg_rxcb(WIFI_IF_STA, wifiRx);
  }

  // WiFi supervision: soft reconnect after 8 s, driver restart after 40 s, reboot after 3 min
  static uint32_t lastChk = 0, lastSoft = 0, lastHard = 0;
  if (now - lastChk > 500) {
    lastChk = now;
    bool a = isAssociated();
    if (a && !wifiUp) { wifiUp = true; Serial.println("\nwifi: connected"); }
    if (!a && wifiUp) { wifiUp = false; wifiDownSince = now; Serial.println("\nwifi: connection lost"); }
    if (!wifiUp) {
      uint32_t down = now - wifiDownSince;
      if (down > 180000) {
        Serial.println("wifi down for 3 min -> restarting ESP");
        delay(100);
        ESP.restart();
      } else if (down > 40000 && now - lastHard > 40000) {
        lastHard = now; reconnects++;
        hardReconnect();
      } else if (down > 8000 && now - lastSoft > 8000) {
        lastSoft = now; reconnects++;
        esp_wifi_disconnect();
        delay(50);
        esp_wifi_connect();
      }
    }
  }

  // Pico silent for 10 s (it sends something every second): re-initialise the UART
  if (now - lastRxMs > 10000) {
    serialReinits++;
    Serial.println("uart: Pico silent, re-initialising UART");
    startSerial1();
  }

  // heartbeat for the Pico, once per second
  static uint32_t lastHb = 0;
  if (now - lastHb > 1000) {
    lastHb = now;
    sendHeartbeat();
  }

  // status lines every 3 s
  static uint32_t lastStat = 0;
  if (now - lastStat > 3000) {
    lastStat = now;
    Serial.printf("[pc->wifi frames=%u dhcpReq=%u txFail=%u err=0x%x srcMacMismatch=%u | wifi->pc frames=%u dhcpReply=%u drops=%u | uartBytes=%u wifi=%d reconnects=%u uartReinit=%u up=%us]\n",
                  (unsigned)frmFromPico, (unsigned)dhcpOut, (unsigned)txFail, lastTxErr, (unsigned)macMismatch,
                  (unsigned)frmToPico, (unsigned)dhcpIn, (unsigned)wifiRxDrops, (unsigned)rxBytes, (int)wifiUp,
                  (unsigned)reconnects, (unsigned)serialReinits, (unsigned)(now / 1000));
    Serial.printf("[PICO: rxBytesFromEsp=%u framesOk=%u framesBad=%u uartOverflow=%u usbSentToPc=%u usbDropped=%u framesFromPc=%u usbReplugs=%u uartResets=%u flags=%u(1=espOnline 2=usbConnected 4=usbReady)]\n",
                  (unsigned)picoStats[0], (unsigned)picoStats[1], (unsigned)picoStats[2], (unsigned)picoStats[3],
                  (unsigned)picoStats[4], (unsigned)picoStats[5], (unsigned)picoStats[6], (unsigned)picoStats[7],
                  (unsigned)picoStats[8], (unsigned)picoStats[9]);
  }
  delay(1);
}