/*
 * ╔══════════════════════════════════════════════════════════════╗
 * ║              SKIMMER HUNTER v2.0 - ESP32                    ║
 * ║      Detector Avanzado de Skimmers Multi-Capa               ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Capas de detección:                                        ║
 * ║  1. Escaneo Bluetooth Classic (SPP/HC-05/HC-06)             ║
 * ║  2. Escaneo BLE (Bluetooth Low Energy)                      ║
 * ║  3. Análisis de prefijos MAC (OUI database)                 ║
 * ║  4. Análisis RSSI contextual                                ║
 * ║  5. Handshake activo (test P→M)                             ║
 * ║  6. Análisis Class-of-Device (CoD)                          ║
 * ║  7. Escaneo WiFi de anomalías                               ║
 * ║  8. Sistema de puntuación (scoring) compuesto               ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Hardware: ESP32 DevKit + OLED SSD1306 + Buzzer + RGB LED   ║
 * ║  Autor: SkimmerHunter Project                               ║
 * ║  Licencia: MIT                                              ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

#include <Arduino.h>
#include "BluetoothSerial.h"
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_bt_device.h"
#include "esp_gap_bt_api.h"
#include "esp_gap_ble_api.h"

// ============================================================
// CONFIGURACIÓN DE HARDWARE
// ============================================================
#define SCREEN_WIDTH    128
#define SCREEN_HEIGHT   64
#define OLED_RESET      -1
#define OLED_ADDR       0x3C

#define BUZZER_PIN      25
#define LED_RED_PIN     27
#define LED_GREEN_PIN   26
#define LED_BLUE_PIN    14
#define BUTTON_SCAN_PIN 33  // Botón para iniciar escaneo
#define BUTTON_MODE_PIN 32  // Botón para cambiar modo

// ============================================================
// CONFIGURACIÓN DE DETECCIÓN
// ============================================================
#define BLE_SCAN_TIME_SEC       10
#define BT_CLASSIC_SCAN_SEC     12
#define WIFI_SCAN_ACTIVE        true
#define MAX_DEVICES             30
#define RSSI_CLOSE_THRESHOLD    -50   // dBm - dispositivo muy cerca
#define RSSI_MEDIUM_THRESHOLD   -70   // dBm - distancia media
#define HANDSHAKE_TIMEOUT_MS    3000
#define SCORE_ALERT_THRESHOLD   5     // Puntuación mínima para alerta

// ============================================================
// NOMBRES SOSPECHOSOS DE SKIMMERS
// ============================================================
const char* SUSPICIOUS_NAMES[] = {
  "HC-03", "HC-05", "HC-06", "HC-08",
  "FREE2MOVE", "RNBT", "ZAPME",
  "BT04-A", "BT-HC05", "linvor",
  "JDY-30", "JDY-31", "JDY-33",
  "AT-09", "HM-10", "HM-11",
  "CC41-A", "MLT-BT05",
  NULL // Terminador
};

// ============================================================
// PREFIJOS MAC (OUI) CONOCIDOS DE MÓDULOS SKIMMER
// Los primeros 3 bytes de la MAC identifican al fabricante
// ============================================================
typedef struct {
  uint8_t oui[3];
  const char* fabricante;
  uint8_t riesgo; // 1-3 (1=bajo, 3=alto)
} OUI_Entry;

const OUI_Entry SUSPICIOUS_OUI[] = {
  // HC-05/HC-06 comunes (fabricantes chinos de módulos BT serie)
  {{0x00, 0x14, 0x03}, "Zhuhai Jieli Technology",     3},
  {{0x98, 0xD3, 0x31}, "Shenzhen HC-Module",          3},
  {{0x20, 0x15, 0x04}, "Guangzhou HC-Info Tech",       3},
  {{0x00, 0x19, 0x10}, "Shenzhen Huicheng",           2},
  {{0x00, 0x21, 0x13}, "HC-Module Generic",            3},
  {{0x30, 0x14, 0x10}, "Shenzhen Module Factory",      2},
  {{0x98, 0xD3, 0x51}, "Shenzhen HC-05 Variant",      3},
  {{0x00, 0x13, 0xEF}, "Shenzhen Linkage",            2},
  {{0x00, 0x15, 0x83}, "Shenzhen BT Generic",         2},
  {{0x20, 0x16, 0x06}, "Jinan USR IOT",               2},
  {{0x98, 0xD3, 0x61}, "HC-06 Extended",               3},
  {{0x00, 0x14, 0xA4}, "Zhuhai Module Works",         2},
  {{0x34, 0x15, 0x13}, "Shenzhen JDY",                3},
  {{0xC8, 0xFD, 0x19}, "Shenzhen Generic BT",         2},
  {{0x00, 0x12, 0x6F}, "Shenzhen Kingsun",            2},
  // JDY / HM / AT módulos
  {{0x7C, 0x01, 0x0A}, "JDY Module Series",           3},
  {{0xF0, 0xC7, 0x7F}, "HM-10/HM-11 Module",         2},
  // Terminador
  {{0x00, 0x00, 0x00}, NULL,                           0}
};

// ============================================================
// ESTRUCTURA DE DISPOSITIVO DETECTADO
// ============================================================
typedef struct {
  char name[64];
  uint8_t mac[6];
  int rssi;
  int score;
  bool isBTClassic;
  bool isBLE;
  bool nameMatch;
  bool ouiMatch;
  bool codSuspicious;
  bool handshakePositive;
  bool rssiClose;
  uint32_t cod;           // Class of Device
  char ouiFabricante[40];
  char scoreDetail[128];
} DetectedDevice;

// ============================================================
// VARIABLES GLOBALES
// ============================================================
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
BluetoothSerial SerialBT;
BLEScan* pBLEScan;

DetectedDevice devices[MAX_DEVICES];
int deviceCount = 0;
int totalBTDevices = 0;
int totalBLEDevices = 0;
int totalWiFiAnomalies = 0;
int highestScore = 0;

enum ScanState {
  STATE_IDLE,
  STATE_SCANNING_BT,
  STATE_SCANNING_BLE,
  STATE_SCANNING_WIFI,
  STATE_HANDSHAKE,
  STATE_RESULTS
};

ScanState currentState = STATE_IDLE;
bool scanRequested = false;
unsigned long lastButtonPress = 0;

// ============================================================
// PROTOTIPOS
// ============================================================
void initHardware();
void initDisplay();
void initBluetooth();
void drawSplashScreen();
void drawIdleScreen();
void drawScanningScreen(const char* phase, int progress);
void drawResultsScreen();
void drawDeviceDetail(int index);
void scanBluetoothClassic();
void scanBLE();
void scanWiFiAnomalies();
bool attemptHandshake(uint8_t* mac);
int checkSuspiciousName(const char* name);
int checkOUI(uint8_t* mac, char* fabricante);
int analyzeRSSI(int rssi);
int analyzeCOD(uint32_t cod);
int calculateScore(DetectedDevice* dev);
void addOrUpdateDevice(const char* name, uint8_t* mac, int rssi,
                       bool btClassic, uint32_t cod);
void sortDevicesByScore();
void setLED(uint8_t r, uint8_t g, uint8_t b);
void alertBuzzer(int level);
void buttonISR();
String macToString(uint8_t* mac);

// ============================================================
// CALLBACK BLUETOOTH CLASSIC - GAP Discovery
// ============================================================
void bt_gap_cb(esp_bt_gap_cb_event_t event, esp_bt_gap_cb_param_t *param) {
  if (event == ESP_BT_GAP_DISC_RES_EVT) {
    totalBTDevices++;
    
    char deviceName[64] = "Unknown";
    uint8_t* mac = param->disc_res.bda;
    uint32_t cod = 0;
    int rssi = -100;
    
    // Extraer propiedades del dispositivo descubierto
    for (int i = 0; i < param->disc_res.num_prop; i++) {
      esp_bt_gap_dev_prop_t* prop = &param->disc_res.prop[i];
      
      switch (prop->type) {
        case ESP_BT_GAP_DEV_PROP_BDNAME: {
          int nameLen = (prop->len > 63) ? 63 : prop->len;
          memcpy(deviceName, prop->val, nameLen);
          deviceName[nameLen] = '\0';
          break;
        }
        case ESP_BT_GAP_DEV_PROP_COD:
          memcpy(&cod, prop->val, sizeof(uint32_t));
          break;
        case ESP_BT_GAP_DEV_PROP_RSSI:
          memcpy(&rssi, prop->val, sizeof(int8_t));
          rssi = (int)(*(int8_t*)prop->val);
          break;
      }
    }
    
    addOrUpdateDevice(deviceName, mac, rssi, true, cod);
    
    Serial.printf("[BT Classic] %s | MAC: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d | CoD: 0x%06X\n",
                  deviceName, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], rssi, cod);
  }
  else if (event == ESP_BT_GAP_DISC_STATE_CHANGED_EVT) {
    if (param->disc_st_chg.state == ESP_BT_GAP_DISCOVERY_STOPPED) {
      Serial.println("[BT Classic] Escaneo completado.");
    }
  }
}

// ============================================================
// CALLBACK BLE - Dispositivos Advertised
// ============================================================
class SkimmerBLECallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) override {
    totalBLEDevices++;
    
    const char* name = "Unknown_BLE";
    if (advertisedDevice.haveName()) {
      name = advertisedDevice.getName().c_str();
    }
    
    uint8_t mac[6];
    memcpy(mac, advertisedDevice.getAddress().getNative(), 6);
    
    int rssi = advertisedDevice.getRSSI();
    
    // BLE no tiene CoD clásico, usamos appearance si existe
    uint32_t cod = 0;
    if (advertisedDevice.haveAppearance()) {
      cod = advertisedDevice.getAppearance();
    }
    
    addOrUpdateDevice(name, mac, rssi, false, cod);
    
    Serial.printf("[BLE] %s | MAC: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d\n",
                  name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], rssi);
  }
};

// ============================================================
// SETUP
// ============================================================
void setup() {
  Serial.begin(115200);
  Serial.println("\n");
  Serial.println("╔══════════════════════════════════════╗");
  Serial.println("║   SKIMMER HUNTER v2.0 - ESP32       ║");
  Serial.println("║   Detector Avanzado Multi-Capa       ║");
  Serial.println("╚══════════════════════════════════════╝");
  
  initHardware();
  initDisplay();
  drawSplashScreen();
  delay(2000);
  
  initBluetooth();
  
  drawIdleScreen();
  Serial.println("[READY] Pulsa el botón SCAN para iniciar detección.");
}

// ============================================================
// LOOP PRINCIPAL
// ============================================================
void loop() {
  // Verificar botón de escaneo
  if (digitalRead(BUTTON_SCAN_PIN) == LOW && 
      millis() - lastButtonPress > 500) {
    lastButtonPress = millis();
    
    if (currentState == STATE_IDLE || currentState == STATE_RESULTS) {
      scanRequested = true;
    }
  }
  
  if (scanRequested) {
    scanRequested = false;
    runFullScan();
  }
  
  // Parpadeo LED según estado
  if (currentState == STATE_IDLE) {
    // Respiración azul suave
    static uint8_t breathVal = 0;
    static int8_t breathDir = 1;
    breathVal += breathDir * 2;
    if (breathVal >= 100 || breathVal <= 0) breathDir = -breathDir;
    setLED(0, 0, breathVal);
    delay(30);
  }
}

// ============================================================
// ESCANEO COMPLETO MULTI-CAPA
// ============================================================
void runFullScan() {
  // Reset
  deviceCount = 0;
  totalBTDevices = 0;
  totalBLEDevices = 0;
  totalWiFiAnomalies = 0;
  highestScore = 0;
  memset(devices, 0, sizeof(devices));
  
  Serial.println("\n========================================");
  Serial.println("  INICIANDO ESCANEO MULTI-CAPA");
  Serial.println("========================================\n");
  
  // ---- FASE 1: Bluetooth Classic ----
  currentState = STATE_SCANNING_BT;
  setLED(0, 0, 255);
  drawScanningScreen("BT Classic", 0);
  Serial.println("[FASE 1/4] Escaneando Bluetooth Classic...");
  scanBluetoothClassic();
  drawScanningScreen("BT Classic", 100);
  
  // ---- FASE 2: BLE ----
  currentState = STATE_SCANNING_BLE;
  setLED(0, 100, 255);
  drawScanningScreen("BLE Scan", 25);
  Serial.println("[FASE 2/4] Escaneando Bluetooth Low Energy...");
  scanBLE();
  drawScanningScreen("BLE Scan", 100);
  
  // ---- FASE 3: WiFi Anomalías ----
  currentState = STATE_SCANNING_WIFI;
  setLED(100, 0, 255);
  drawScanningScreen("WiFi Scan", 50);
  Serial.println("[FASE 3/4] Escaneando anomalías WiFi...");
  scanWiFiAnomalies();
  drawScanningScreen("WiFi Scan", 100);
  
  // ---- FASE 4: Handshake activo a sospechosos ----
  currentState = STATE_HANDSHAKE;
  setLED(255, 100, 0);
  drawScanningScreen("Handshake", 75);
  Serial.println("[FASE 4/4] Intentando handshake con sospechosos...");
  
  for (int i = 0; i < deviceCount; i++) {
    if (devices[i].score >= 3 && devices[i].isBTClassic) {
      Serial.printf("  -> Intentando handshake con %s...\n", devices[i].name);
      devices[i].handshakePositive = attemptHandshake(devices[i].mac);
      if (devices[i].handshakePositive) {
        Serial.printf("  !! HANDSHAKE POSITIVO: %s es un SKIMMER CONFIRMADO\n", devices[i].name);
      }
      // Recalcular score
      devices[i].score = calculateScore(&devices[i]);
    }
  }
  
  // ---- Ordenar por score y mostrar resultados ----
  sortDevicesByScore();
  
  // Encontrar score más alto
  highestScore = (deviceCount > 0) ? devices[0].score : 0;
  
  // ---- Alertas ----
  currentState = STATE_RESULTS;
  
  if (highestScore >= SCORE_ALERT_THRESHOLD) {
    setLED(255, 0, 0); // ROJO = Peligro
    alertBuzzer(highestScore);
  } else if (highestScore >= 3) {
    setLED(255, 150, 0); // NARANJA = Sospechoso
    alertBuzzer(2);
  } else {
    setLED(0, 255, 0); // VERDE = Limpio
    alertBuzzer(0);
  }
  
  drawResultsScreen();
  printFullReport();
}

// ============================================================
// ESCANEO BLUETOOTH CLASSIC
// ============================================================
void scanBluetoothClassic() {
  // Registrar callback GAP
  esp_bt_gap_register_callback(bt_gap_cb);
  
  // Iniciar descubrimiento (inquiry)
  // Modo: General discovery, duración en unidades de 1.28s
  esp_bt_gap_start_discovery(ESP_BT_INQ_MODE_GENERAL_INQUIRY, 
                              BT_CLASSIC_SCAN_SEC / 1.28, 0);
  
  // Esperar a que termine
  unsigned long startTime = millis();
  while (millis() - startTime < (BT_CLASSIC_SCAN_SEC * 1000UL + 2000)) {
    delay(100);
    int progress = (millis() - startTime) * 100 / (BT_CLASSIC_SCAN_SEC * 1000UL);
    if (progress > 100) progress = 100;
    drawScanningScreen("BT Classic", progress);
  }
  
  esp_bt_gap_cancel_discovery();
  Serial.printf("[BT Classic] Total dispositivos encontrados: %d\n", totalBTDevices);
}

// ============================================================
// ESCANEO BLE
// ============================================================
void scanBLE() {
  BLEDevice::init("SkimmerHunter");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new SkimmerBLECallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);
  
  BLEScanResults foundDevices = pBLEScan->start(BLE_SCAN_TIME_SEC, false);
  
  Serial.printf("[BLE] Total dispositivos encontrados: %d\n", totalBLEDevices);
  
  pBLEScan->clearResults();
  BLEDevice::deinit(false);
}

// ============================================================
// ESCANEO WIFI - Buscar anomalías
// ============================================================
void scanWiFiAnomalies() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  int n = WiFi.scanNetworks(false, true); // incluir ocultas
  
  Serial.printf("[WiFi] Redes encontradas: %d\n", n);
  
  for (int i = 0; i < n; i++) {
    String ssid = WiFi.SSID(i);
    int rssi = WiFi.RSSI(i);
    int channel = WiFi.channel(i);
    
    bool suspicious = false;
    String reason = "";
    
    // Red oculta con señal fuerte cerca
    if (ssid.length() == 0 && rssi > RSSI_CLOSE_THRESHOLD) {
      suspicious = true;
      reason = "Red oculta con señal fuerte";
    }
    
    // Nombres sospechosos de redes ad-hoc de skimmers
    const char* wifiSuspNames[] = {
      "HC-", "skimmer", "card", "reader", "pump",
      "ESP_", "ESP32", "arduino", "module", NULL
    };
    
    for (int j = 0; wifiSuspNames[j] != NULL; j++) {
      if (ssid.indexOf(wifiSuspNames[j]) >= 0) {
        suspicious = true;
        reason = "Nombre WiFi sospechoso: " + ssid;
        break;
      }
    }
    
    if (suspicious) {
      totalWiFiAnomalies++;
      Serial.printf("[WiFi ANOMALÍA] SSID: '%s' | RSSI: %d | CH: %d | %s\n",
                    ssid.c_str(), rssi, channel, reason.c_str());
    }
  }
  
  WiFi.scanDelete();
  WiFi.mode(WIFI_OFF);
  
  Serial.printf("[WiFi] Anomalías detectadas: %d\n", totalWiFiAnomalies);
}

// ============================================================
// HANDSHAKE ACTIVO - Test P → M
// ============================================================
bool attemptHandshake(uint8_t* mac) {
  const char* defaultPasswords[] = {"1234", "0000", "1111", "6789", NULL};
  
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  
  // Intentar conexión SPP con contraseñas por defecto
  for (int p = 0; defaultPasswords[p] != NULL; p++) {
    Serial.printf("    Intentando conexión SPP con PIN: %s\n", defaultPasswords[p]);
    
    // Configurar PIN
    esp_bt_pin_code_t pin;
    memcpy(pin, defaultPasswords[p], strlen(defaultPasswords[p]));
    esp_bt_gap_set_pin(ESP_BT_PIN_TYPE_FIXED, strlen(defaultPasswords[p]), pin);
    
    // Intentar conectar via SerialBT
    bool connected = SerialBT.connect(mac);
    
    if (connected) {
      Serial.println("    -> Conectado! Enviando test 'P'...");
      delay(500);
      
      SerialBT.write('P');
      SerialBT.flush();
      
      unsigned long startWait = millis();
      while (!SerialBT.available() && millis() - startWait < HANDSHAKE_TIMEOUT_MS) {
        delay(50);
      }
      
      if (SerialBT.available()) {
        char response = SerialBT.read();
        Serial.printf("    -> Respuesta recibida: '%c' (0x%02X)\n", response, response);
        
        SerialBT.disconnect();
        
        if (response == 'M') {
          Serial.println("    ███ SKIMMER CONFIRMADO POR HANDSHAKE ███");
          return true;
        }
        
        // Otros caracteres de respuesta conocidos
        if (response == '1' || response == 'C') {
          Serial.println("    -> Respuesta sospechosa (variante de skimmer)");
          return true;
        }
      } else {
        Serial.println("    -> Sin respuesta (timeout)");
      }
      
      SerialBT.disconnect();
    } else {
      Serial.println("    -> Conexión fallida con este PIN");
    }
    
    delay(500);
  }
  
  return false;
}

// ============================================================
// ANÁLISIS: Nombre sospechoso
// ============================================================
int checkSuspiciousName(const char* name) {
  if (name == NULL || strlen(name) == 0 || strcmp(name, "Unknown") == 0) {
    return 0;
  }
  
  // Coincidencia exacta
  for (int i = 0; SUSPICIOUS_NAMES[i] != NULL; i++) {
    if (strcasecmp(name, SUSPICIOUS_NAMES[i]) == 0) {
      return 3; // Match exacto = +3
    }
  }
  
  // Coincidencia parcial
  String nameUpper = String(name);
  nameUpper.toUpperCase();
  
  for (int i = 0; SUSPICIOUS_NAMES[i] != NULL; i++) {
    String suspect = String(SUSPICIOUS_NAMES[i]);
    suspect.toUpperCase();
    if (nameUpper.indexOf(suspect) >= 0) {
      return 2; // Match parcial = +2
    }
  }
  
  return 0;
}

// ============================================================
// ANÁLISIS: Prefijo MAC (OUI)
// ============================================================
int checkOUI(uint8_t* mac, char* fabricante) {
  for (int i = 0; SUSPICIOUS_OUI[i].fabricante != NULL; i++) {
    if (mac[0] == SUSPICIOUS_OUI[i].oui[0] &&
        mac[1] == SUSPICIOUS_OUI[i].oui[1] &&
        mac[2] == SUSPICIOUS_OUI[i].oui[2]) {
      strncpy(fabricante, SUSPICIOUS_OUI[i].fabricante, 39);
      fabricante[39] = '\0';
      return SUSPICIOUS_OUI[i].riesgo; // Retorna nivel de riesgo 1-3
    }
  }
  
  fabricante[0] = '\0';
  return 0;
}

// ============================================================
// ANÁLISIS: RSSI (proximidad)
// ============================================================
int analyzeRSSI(int rssi) {
  if (rssi > RSSI_CLOSE_THRESHOLD) {
    return 2; // Muy cerca = +2 (probablemente dentro de la máquina)
  } else if (rssi > RSSI_MEDIUM_THRESHOLD) {
    return 1; // Distancia media = +1
  }
  return 0;
}

// ============================================================
// ANÁLISIS: Class of Device
// ============================================================
int analyzeCOD(uint32_t cod) {
  if (cod == 0) return 1; // Sin CoD / Uncategorized = sospechoso
  
  // Extraer Major Device Class (bits 8-12)
  uint8_t majorClass = (cod >> 8) & 0x1F;
  // Extraer Minor Device Class (bits 2-7)
  uint8_t minorClass = (cod >> 2) & 0x3F;
  
  // CoD "Uncategorized" = 0x000000
  if (majorClass == 0 && minorClass == 0) {
    return 2; // Muy sospechoso
  }
  
  // Dispositivos de red/transferencia que no deberían estar en un ATM
  // Major class 3 = Networking, no común en entornos de pago
  if (majorClass == 3) {
    return 1;
  }
  
  return 0;
}

// ============================================================
// CÁLCULO DE PUNTUACIÓN TOTAL
// ============================================================
int calculateScore(DetectedDevice* dev) {
  int score = 0;
  char detail[128] = "";
  char temp[32];
  
  // 1. Nombre sospechoso (0-3 puntos)
  int nameScore = checkSuspiciousName(dev->name);
  if (nameScore > 0) {
    dev->nameMatch = true;
    score += nameScore;
    snprintf(temp, sizeof(temp), "N:%d ", nameScore);
    strcat(detail, temp);
  }
  
  // 2. OUI/MAC prefix (0-3 puntos)
  int ouiScore = checkOUI(dev->mac, dev->ouiFabricante);
  if (ouiScore > 0) {
    dev->ouiMatch = true;
    score += ouiScore;
    snprintf(temp, sizeof(temp), "O:%d ", ouiScore);
    strcat(detail, temp);
  }
  
  // 3. RSSI proximidad (0-2 puntos)
  int rssiScore = analyzeRSSI(dev->rssi);
  if (rssiScore > 0) {
    dev->rssiClose = true;
    score += rssiScore;
    snprintf(temp, sizeof(temp), "R:%d ", rssiScore);
    strcat(detail, temp);
  }
  
  // 4. Class of Device (0-2 puntos)
  int codScore = analyzeCOD(dev->cod);
  if (codScore > 0) {
    dev->codSuspicious = true;
    score += codScore;
    snprintf(temp, sizeof(temp), "C:%d ", codScore);
    strcat(detail, temp);
  }
  
  // 5. Handshake positivo (0 o 5 puntos) - CONFIRMACIÓN DIRECTA
  if (dev->handshakePositive) {
    score += 5;
    strcat(detail, "H:5 ");
  }
  
  // 6. Bonus: BT Classic sin nombre o nombre genérico = +1
  if (dev->isBTClassic && 
      (strlen(dev->name) == 0 || strcmp(dev->name, "Unknown") == 0)) {
    score += 1;
    strcat(detail, "U:1 ");
  }
  
  strncpy(dev->scoreDetail, detail, sizeof(dev->scoreDetail) - 1);
  return score;
}

// ============================================================
// AÑADIR O ACTUALIZAR DISPOSITIVO
// ============================================================
void addOrUpdateDevice(const char* name, uint8_t* mac, int rssi,
                       bool btClassic, uint32_t cod) {
  // Buscar si ya existe
  for (int i = 0; i < deviceCount; i++) {
    if (memcmp(devices[i].mac, mac, 6) == 0) {
      // Actualizar info si encontramos más datos
      if (name && strlen(name) > 0 && strcmp(name, "Unknown") != 0 &&
          strcmp(name, "Unknown_BLE") != 0) {
        strncpy(devices[i].name, name, 63);
      }
      if (rssi > devices[i].rssi) devices[i].rssi = rssi; // Mejor señal
      if (btClassic) devices[i].isBTClassic = true;
      if (!btClassic) devices[i].isBLE = true;
      if (cod != 0) devices[i].cod = cod;
      devices[i].score = calculateScore(&devices[i]);
      return;
    }
  }
  
  // Nuevo dispositivo
  if (deviceCount < MAX_DEVICES) {
    DetectedDevice* dev = &devices[deviceCount];
    memset(dev, 0, sizeof(DetectedDevice));
    
    strncpy(dev->name, name ? name : "Unknown", 63);
    memcpy(dev->mac, mac, 6);
    dev->rssi = rssi;
    dev->isBTClassic = btClassic;
    dev->isBLE = !btClassic;
    dev->cod = cod;
    
    dev->score = calculateScore(dev);
    deviceCount++;
  }
}

// ============================================================
// ORDENAR DISPOSITIVOS POR SCORE (MAYOR PRIMERO)
// ============================================================
void sortDevicesByScore() {
  for (int i = 0; i < deviceCount - 1; i++) {
    for (int j = 0; j < deviceCount - i - 1; j++) {
      if (devices[j].score < devices[j + 1].score) {
        DetectedDevice temp = devices[j];
        devices[j] = devices[j + 1];
        devices[j + 1] = temp;
      }
    }
  }
}

// ============================================================
// IMPRIMIR REPORTE COMPLETO POR SERIAL
// ============================================================
void printFullReport() {
  Serial.println("\n╔══════════════════════════════════════════════════════════════╗");
  Serial.println("║                  REPORTE DE DETECCIÓN                       ║");
  Serial.println("╠══════════════════════════════════════════════════════════════╣");
  Serial.printf("║ Dispositivos BT Classic: %-5d | BLE: %-5d                  ║\n",
                totalBTDevices, totalBLEDevices);
  Serial.printf("║ Anomalías WiFi: %-5d                                       ║\n",
                totalWiFiAnomalies);
  Serial.printf("║ Dispositivos sospechosos: %-5d                              ║\n",
                deviceCount);
  Serial.println("╠══════════════════════════════════════════════════════════════╣");
  
  for (int i = 0; i < deviceCount; i++) {
    DetectedDevice* d = &devices[i];
    
    // Solo mostrar los que tienen score > 0
    if (d->score <= 0) continue;
    
    const char* threat = "BAJO";
    if (d->score >= SCORE_ALERT_THRESHOLD) threat = "¡¡ALTO!!";
    else if (d->score >= 3) threat = "MEDIO";
    
    Serial.printf("║ #%d  [SCORE: %2d] [%s]                               \n",
                  i + 1, d->score, threat);
    Serial.printf("║   Nombre: %-40s           \n", d->name);
    Serial.printf("║   MAC:    %02X:%02X:%02X:%02X:%02X:%02X              \n",
                  d->mac[0], d->mac[1], d->mac[2],
                  d->mac[3], d->mac[4], d->mac[5]);
    Serial.printf("║   RSSI:   %d dBm | Tipo: %s%s               \n",
                  d->rssi,
                  d->isBTClassic ? "BT" : "",
                  d->isBLE ? "BLE" : "");
    Serial.printf("║   CoD:    0x%06X                                 \n", d->cod);
    Serial.printf("║   Score:  %s                                      \n", d->scoreDetail);
    
    Serial.print("║   Flags:  ");
    if (d->nameMatch) Serial.print("[NOMBRE] ");
    if (d->ouiMatch) Serial.printf("[OUI:%s] ", d->ouiFabricante);
    if (d->rssiClose) Serial.print("[CERCA] ");
    if (d->codSuspicious) Serial.print("[CoD_SUSP] ");
    if (d->handshakePositive) Serial.print("[¡¡HANDSHAKE!!] ");
    Serial.println();
    
    if (d->handshakePositive) {
      Serial.println("║   ████████████████████████████████████████████████");
      Serial.println("║   █  ¡¡¡SKIMMER CONFIRMADO POR HANDSHAKE!!!    █");
      Serial.println("║   ████████████████████████████████████████████████");
    }
    
    Serial.println("║──────────────────────────────────────────────────────────────");
  }
  
  Serial.println("╠══════════════════════════════════════════════════════════════╣");
  
  if (highestScore >= SCORE_ALERT_THRESHOLD) {
    Serial.println("║  ⚠⚠⚠  ALERTA: POSIBLE SKIMMER DETECTADO  ⚠⚠⚠               ║");
    Serial.println("║  NO USES ESTE TERMINAL. NOTIFICA A LAS AUTORIDADES.        ║");
  } else if (highestScore >= 3) {
    Serial.println("║  ⚠ PRECAUCIÓN: Dispositivos sospechosos encontrados         ║");
    Serial.println("║  Usa con precaución. Considera pago contactless.            ║");
  } else {
    Serial.println("║  ✓ ZONA APARENTEMENTE LIMPIA                                ║");
    Serial.println("║  No se detectaron skimmers. Aún así, usa contactless.       ║");
  }
  
  Serial.println("╚══════════════════════════════════════════════════════════════╝\n");
}

// ============================================================
// FUNCIONES DE HARDWARE
// ============================================================
void initHardware() {
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(LED_RED_PIN, OUTPUT);
  pinMode(LED_GREEN_PIN, OUTPUT);
  pinMode(LED_BLUE_PIN, OUTPUT);
  pinMode(BUTTON_SCAN_PIN, INPUT_PULLUP);
  pinMode(BUTTON_MODE_PIN, INPUT_PULLUP);
  
  // PWM para LED RGB
  ledcSetup(0, 5000, 8);
  ledcSetup(1, 5000, 8);
  ledcSetup(2, 5000, 8);
  ledcAttachPin(LED_RED_PIN, 0);
  ledcAttachPin(LED_GREEN_PIN, 1);
  ledcAttachPin(LED_BLUE_PIN, 2);
  
  setLED(0, 0, 0);
  
  Serial.println("[HW] Hardware inicializado.");
}

void initDisplay() {
  Wire.begin();
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println("[ERROR] No se encontró pantalla OLED!");
    // Continuar sin pantalla
  } else {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.display();
    Serial.println("[HW] Pantalla OLED inicializada.");
  }
}

void initBluetooth() {
  // Inicializar Bluetooth Classic
  if (!btStart()) {
    Serial.println("[ERROR] No se pudo iniciar Bluetooth!");
    return;
  }
  
  if (esp_bluedroid_init() != ESP_OK) {
    Serial.println("[ERROR] Bluedroid init falló!");
    return;
  }
  
  if (esp_bluedroid_enable() != ESP_OK) {
    Serial.println("[ERROR] Bluedroid enable falló!");
    return;
  }
  
  SerialBT.begin("SkimHunter", true); // Master mode
  
  Serial.println("[BT] Bluetooth inicializado (Classic + BLE).");
}

// ============================================================
// FUNCIONES DE DISPLAY OLED
// ============================================================
void drawSplashScreen() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(10, 5);
  display.print("SKIMMER HUNTER");
  display.setCursor(45, 18);
  display.setTextSize(2);
  display.print("v2.0");
  display.setTextSize(1);
  display.setCursor(15, 40);
  display.print("Multi-Layer Scan");
  display.setCursor(10, 52);
  display.print("BT+BLE+WiFi+Hshake");
  display.display();
}

void drawIdleScreen() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(5, 5);
  display.print("SKIMMER HUNTER v2.0");
  display.drawLine(0, 15, 128, 15, SSD1306_WHITE);
  display.setCursor(5, 22);
  display.print("Estado: LISTO");
  display.setCursor(5, 35);
  display.print("Pulsa SCAN para");
  display.setCursor(5, 45);
  display.print("iniciar deteccion");
  display.drawRect(20, 55, 88, 9, SSD1306_WHITE);
  display.setCursor(33, 56);
  display.print("[SCAN]");
  display.display();
}

void drawScanningScreen(const char* phase, int progress) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(5, 2);
  display.print("ESCANEANDO...");
  display.setCursor(5, 15);
  display.printf("Fase: %s", phase);
  
  // Barra de progreso
  display.drawRect(5, 30, 118, 10, SSD1306_WHITE);
  int barWidth = (progress * 114) / 100;
  display.fillRect(7, 32, barWidth, 6, SSD1306_WHITE);
  
  display.setCursor(50, 44);
  display.printf("%d%%", progress);
  
  display.setCursor(5, 55);
  display.printf("BT:%d BLE:%d WiFi:%d",
                 totalBTDevices, totalBLEDevices, totalWiFiAnomalies);
  display.display();
}

void drawResultsScreen() {
  display.clearDisplay();
  display.setTextSize(1);
  
  if (highestScore >= SCORE_ALERT_THRESHOLD) {
    // ALERTA
    display.fillRect(0, 0, 128, 12, SSD1306_WHITE);
    display.setTextColor(SSD1306_BLACK);
    display.setCursor(5, 2);
    display.print("!! SKIMMER ALERTA !!");
    display.setTextColor(SSD1306_WHITE);
  } else if (highestScore >= 3) {
    display.setCursor(5, 2);
    display.print("! SOSPECHOSO !");
  } else {
    display.setCursor(5, 2);
    display.print("* ZONA LIMPIA *");
  }
  
  display.drawLine(0, 14, 128, 14, SSD1306_WHITE);
  
  display.setCursor(0, 18);
  display.printf("BT:%d BLE:%d W:%d",
                 totalBTDevices, totalBLEDevices, totalWiFiAnomalies);
  
  // Mostrar top 3 dispositivos sospechosos
  int shown = 0;
  for (int i = 0; i < deviceCount && shown < 3; i++) {
    if (devices[i].score > 0) {
      int y = 30 + (shown * 11);
      display.setCursor(0, y);
      display.printf("S:%d %s", devices[i].score, devices[i].name);
      shown++;
    }
  }
  
  if (shown == 0) {
    display.setCursor(5, 35);
    display.print("Sin amenazas");
    display.setCursor(5, 48);
    display.print("detectadas");
  }
  
  display.display();
}

// ============================================================
// LED RGB
// ============================================================
void setLED(uint8_t r, uint8_t g, uint8_t b) {
  ledcWrite(0, r);
  ledcWrite(1, g);
  ledcWrite(2, b);
}

// ============================================================
// BUZZER - ALERTAS SONORAS
// ============================================================
void alertBuzzer(int level) {
  if (level >= SCORE_ALERT_THRESHOLD) {
    // Alarma alta: 3 pitidos largos agudos
    for (int i = 0; i < 3; i++) {
      tone(BUZZER_PIN, 2800, 400);
      delay(500);
      tone(BUZZER_PIN, 3200, 400);
      delay(500);
    }
  } else if (level >= 3) {
    // Alerta media: 2 pitidos cortos
    for (int i = 0; i < 2; i++) {
      tone(BUZZER_PIN, 1800, 200);
      delay(300);
    }
  } else if (level > 0) {
    // Aviso bajo: 1 pitido suave
    tone(BUZZER_PIN, 1000, 150);
  } else {
    // Todo limpio: tono positivo
    tone(BUZZER_PIN, 800, 100);
    delay(150);
    tone(BUZZER_PIN, 1200, 100);
  }
  
  noTone(BUZZER_PIN);
}

// ============================================================
// UTILIDADES
// ============================================================
String macToString(uint8_t* mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}
