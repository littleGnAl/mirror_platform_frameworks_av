#include <fuzzer/FuzzedDataProvider.h>
#include "InitDataParser.h"
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  FuzzedDataProvider fuzzed_data(data, size);
  android::hardware::drm::V1_2::clearkey::InitDataParser parser;

  // declare initData parameter and determine size
  std::vector<uint8_t> initData;
  uint16_t initDataSize;
  if (fuzzed_data.ConsumeBool()) {
    initDataSize = 16; // 16 is the required size for Webm MimeType's
  }
  else {
    initDataSize = fuzzed_data.ConsumeIntegral<uint16_t>();
    initDataSize = std::max(initDataSize, (uint16_t)1);
    // Vector size of 0 will cause a crash.
 }

  // insert size field into initData as uint8_t's
  if (fuzzed_data.ConsumeBool()){
    uint32_t sizeField = ntohl((uint32_t) initDataSize);
    for (int i = 0; i < 4; ++i) {
      initData.push_back(sizeField % 256);
      sizeField=sizeField / 256;
    }
  }

  // insert PSSH box identifier into initData
  if (fuzzed_data.ConsumeBool()) {
    initData.insert(initData.end(), {'p', 's', 's', 'h'});
  }

  // insert EME version number into initData
  if (fuzzed_data.ConsumeBool()) {
    initData.insert(initData.end(), {1, 0, 0, 0});
  }

  // insert system ID into initData
  switch (fuzzed_data.ConsumeIntegral<uint8_t>() % 3) {
    case 0:
      initData.insert(initData.end(), {0x10,0x77,0xEF,0xEC,0xC0,0xB2,0x4D,0x02,
        0xAC,0xE3,0x3C,0x1E,0x52,0xE2,0xFB,0x4B});
      break;
    case 1:
      initData.insert(initData.end(), {0xE2,0x71,0x9D,0x58,0xA9,0x85,0xB3,0xC9,
        0x78,0x1A,0xB0,0x30,0xAF,0x78,0xD3,0x0E});
      break;
    default:
      break;
  }

  // insert key ID count into initData as uint8_t's
  if (fuzzed_data.ConsumeBool()) {
    uint32_t keyIdBytes = initDataSize - initData.size() - 2*sizeof(uint32_t);
    uint32_t keyIdCount = htonl((keyIdBytes/16));
    for (int i = 0; i < 4; ++i) {
      initData.push_back(keyIdCount % 256);
      keyIdCount = keyIdCount / 256;
    }
  }

  // insert random uint8_t's into initData until full
  for (size_t i = initData.size(); i < initDataSize; i++) {
    initData.push_back(fuzzed_data.ConsumeIntegral<uint8_t>());
  }

  // initialize mimeType parameter
  std::string mimeType;
  switch (fuzzed_data.ConsumeIntegral<uint8_t>() % 7) {
    case 0:
      mimeType = "cenc";
      break;
    case 1:
      mimeType = "audio/mp4";
      break;
    case 2:
      mimeType = "video/mp4";
      break;
    case 3:
      mimeType = "webm";
      break;
    case 4:
      mimeType = "audio/webm";
      break;
    case 5:
      mimeType = "video/webm";
      break;
    default:
      mimeType = fuzzed_data.ConsumeBytesAsString(8);
  }

  // initialize keyType parameter
  android::hardware::drm::V1_0::KeyType keyType;
  switch (fuzzed_data.ConsumeIntegral<uint8_t>() % 3){
    case 0:
      keyType = android::hardware::drm::V1_0::KeyType::OFFLINE;
      break;
    case 1:
      keyType = android::hardware::drm::V1_0::KeyType::STREAMING;
      break;
    default:
      keyType = android::hardware::drm::V1_0::KeyType::RELEASE;
  }

  // declare licenseRequest parameter and fill with uint8_t's
  std::vector<uint8_t> licenseRequest;
  uint16_t licenseRequestSize = fuzzed_data.ConsumeIntegral<uint16_t>();
  for (uint16_t i = 0; i < licenseRequestSize; ++i) {
    licenseRequest.push_back(fuzzed_data.ConsumeIntegral<uint8_t>());
  }

  parser.parse(initData, mimeType, keyType, &licenseRequest);

  return 0;
}

