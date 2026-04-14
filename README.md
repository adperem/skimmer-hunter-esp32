# 🔍 Skimmer Hunter ESP32

> **Detect Bluetooth credit card skimmers in ATMs and fuel pumps — for ~€15 in parts.**

![Platform](https://img.shields.io/badge/platform-ESP32-blue?logo=espressif)
![Language](https://img.shields.io/badge/language-Arduino%20C%2B%2B-informational)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

---

## 🧠 What is this?

Skimmer Hunter is an open-source ESP32 firmware that detects Bluetooth-enabled credit card skimmers hidden inside ATMs, gas pumps, and point-of-sale terminals.

It uses an **8-layer detection engine** that goes far beyond simply scanning for nearby Bluetooth devices — it analyzes MAC prefixes, signal proximity, device class, WiFi anomalies, and even attempts an active handshake to confirm the presence of a skimmer with near-certainty.

---

## ⚙️ Detection Layers

| Layer | Method | What it catches |
|-------|--------|----------------|
| 1 | Classic Bluetooth scan | HC-05/HC-06 modules |
| 2 | BLE scan | BLE-based skimmers |
| 3 | OUI fingerprinting | Known skimmer chip vendors |
| 4 | RSSI proximity analysis | Devices physically inside the machine |
| 5 | Class of Device (CoD) | Unconfigured "Uncategorized" modules |
| 6 | WiFi anomaly detection | Hidden SSIDs, ESP32/Arduino APs |
| 7 | Active PIN handshake | Sends "P", waits for "M" confirmation |
| 8 | Composite scoring | Score ≥5 = 🔴 Alert, 3-4 = 🟡 Suspicious |

---

## 🛠️ Hardware Required

| Component | Approx. cost |
|-----------|-------------|
| ESP32 DevKit v1 | €4 |
| OLED SSD1306 0.96" (I2C) | €3 |
| Passive buzzer | €0.50 |
| RGB LED (common cathode) | €0.50 |
| 2x push buttons | €0.50 |
| Resistors (220Ω ×3, 10kΩ ×2, 100Ω ×1) | €0.50 |
| Breadboard + wires | €3 |
| **Total** | **~€12–15** |

---

## 🔌 Wiring

```
ESP32 GPIO  →  Component
─────────────────────────
GPIO 21     →  OLED SDA
GPIO 22     →  OLED SCL
GPIO 25     →  Buzzer (+)
GPIO 27     →  RGB Red   (220Ω)
GPIO 26     →  RGB Green (220Ω)
GPIO 14     →  RGB Blue  (220Ω)
GPIO 33     →  Scan button (10kΩ pull-up)
GPIO 32     →  Mode button (10kΩ pull-up)
3.3V / GND →  All VCC / GND rails
```

---

## 🚀 Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/adperem/skimmer-hunter-esp32.git
cd skimmer-hunter-esp32
```

### 2. Install dependencies (Arduino IDE)

- `Adafruit SSD1306`
- `Adafruit GFX Library`
- ESP32 board support via Boards Manager (`https://dl.espressif.com/dl/package_esp32_index.json`)

### 3. Flash

Open `SkimmerHunter.ino` in Arduino IDE, select your board (`ESP32 Dev Module`), and hit **Upload**.

---

## 📱 How to use it

1. Power on the device — the OLED shows the boot screen.
2. **Press SCAN** near an ATM or fuel pump.
3. The device scans all Bluetooth Classic, BLE, and WiFi channels simultaneously.
4. Each detected device is scored:
   - 🟢 **0–2 pts** → Clean
   - 🟡 **3–4 pts** → Suspicious
   - 🔴 **≥5 pts** → Likely skimmer — buzzer alert + red LED
5. If a suspicious device is found, the device attempts an active handshake (PIN `1234` / `0000`, sends `"P"`). A reply of `"M"` is near-definitive confirmation.

> ⚠️ **If you find a skimmer, do not remove it. Report it to local authorities or the business owner immediately.**

---

## 📊 Scoring example

```
Device found: "HC-06" | MAC: 20:16:02:xx:xx:xx | RSSI: -42 dBm
─────────────────────────────────────────────────────────────────
  + OUI match (HC-06 vendor)        → +3 pts
  + RSSI inside range (<-50 dBm)    → +2 pts
  + CoD: Uncategorized              → +1 pt
  + Name pattern match              → +1 pt
─────────────────────────────────────────────────────────────────
  Total score: 7/10  →  🔴 SKIMMER ALERT
```

---

## 🗺️ Roadmap

- [ ] SD card logging with GPS coordinates
- [ ] Web dashboard over WiFi (view results on your phone)
- [ ] OTA OUI database updates
- [ ] M5Stack / LilyGO T-Display port
- [ ] Flipper Zero companion app

---

## 📖 Blog post

Full write-up with detailed code explanations, wiring diagrams, and real-world test results:

👉 [adperem.github.io — Skimmer Hunter v2.0](https://adperem.github.io/posts/skimmer-hunter-esp32/)

---

## 📚 References

- [SparkFun — Gas Pump Skimmers teardown](https://learn.sparkfun.com/tutorials/gas-pump-skimmers/)
- [UC San Diego — Bluetana research paper](https://cseweb.ucsd.edu/~nibhaska/bluetana.pdf)
- [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)

---

## 📄 License

MIT © [adperem](https://github.com/adperem)
