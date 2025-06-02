#include <Arduino.h>
#include <WiFi.h>
#include <time.h>
#include <mbedtls/md.h>
#include <NTPClient.h>
#include <WiFiUdp.h>
//#include <ESP8266WiFi.h>

// Replace with your 16-character base32 secret
const char* secret32 = "WPHR3VQGVNGRICXN";

// Minimal Base32 decode for 16-char secrets (no padding, uppercase only)
void base32_decode(const char* encoded, uint8_t* output) {
  const char* base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  for (int i = 0, j = 0; i < 16;) {
    uint32_t buffer = 0;
    int bitsLeft = 0;
    for (int k = 0; k < 8 && i < 16; ++k, ++i) {
      char* p = strchr(base32_chars, toupper(encoded[i]));
      buffer <<= 5;
      if (p) buffer |= (p - base32_chars);
      bitsLeft += 5;
      if (bitsLeft >= 8) {
        output[j++] = (buffer >> (bitsLeft - 8)) & 0xFF;
        bitsLeft -= 8;
      }
    }
  }
}

// Pack time into 8 bytes (big endian)
void pack_time(uint64_t counter, uint8_t* buf) {
  for (int i = 7; i >= 0; --i) {
    buf[i] = counter & 0xFF;
    counter >>= 8;
  }
}

// Dynamic truncate per RFC4226
uint32_t dynamic_truncate(uint8_t* hash) {
  int offset = hash[19] & 0x0F;
  uint32_t bin_code = ((hash[offset] & 0x7F) << 24) |
                      ((hash[offset + 1] & 0xFF) << 16) |
                      ((hash[offset + 2] & 0xFF) << 8) |
                      (hash[offset + 3] & 0xFF);
  return bin_code;
}

// WiFi credentials
const char *ssid     = "Your-wifi-ssid";
const char *password = "password wiifi";

WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP, "pool.ntp.org", 0, 60000); // 0 offset for UTC

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
  timeClient.begin();
  timeClient.update();
}

void loop() {
  timeClient.update();
  unsigned long epochTime = timeClient.getEpochTime();
  unsigned long counter = epochTime / 30;

  // Decode secret
  uint8_t secret[10] = {0};
  base32_decode(secret32, secret);

  // Pack counter
  uint8_t packed_counter[8];
  pack_time(counter, packed_counter);

  // HMAC-SHA1
  uint8_t hash[20];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
  mbedtls_md_hmac_starts(&ctx, secret, 10);
  mbedtls_md_hmac_update(&ctx, packed_counter, 8);
  mbedtls_md_hmac_finish(&ctx, hash);
  mbedtls_md_free(&ctx);

  // Dynamic truncate and get 6 digits
  uint32_t code = dynamic_truncate(hash);
  code = code % 1000000;

  // Print UTC time and info
  Serial.printf("UTC Time: %s | Epoch: %lu | Counter: %lu | TOTP: %06u\n", timeClient.getFormattedTime().c_str(), epochTime, counter, code);
  delay(1000);
}
