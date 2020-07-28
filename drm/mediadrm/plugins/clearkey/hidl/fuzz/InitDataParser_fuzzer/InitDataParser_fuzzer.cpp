/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fuzzer/FuzzedDataProvider.h>
#include "InitDataParser.h"

void pushUint32_t(std::vector<uint8_t> &vect, uint32_t num) {
  for (int i = 0; i < 4; ++i) {
    vect.push_back(num % 256);
    num = num / 256;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  android::hardware::drm::V1_2::clearkey::InitDataParser parser;

  // Declare initData parameter and determine size
  std::vector<uint8_t> initData;
  uint16_t initDataSize;
  if (fuzzed_data.ConsumeBool()) {
    initDataSize = 16;  // 16 is the required size for Webm MimeType's
  } else {
    initDataSize = fuzzed_data.ConsumeIntegralInRange<uint16_t>(1, UINT16_MAX);
    // Vector size of 0 will cause a crash.
  }

  // Insert size field into initData as uint8_t's
  if (fuzzed_data.ConsumeBool()) {
    uint32_t sizeField = ntohl((uint32_t) initDataSize);
    pushUint32_t(initData, sizeField);
  }

  // Insert PSSH box identifier into initData
  if (fuzzed_data.ConsumeBool()) {
    initData.insert(initData.end(), {'p', 's', 's', 'h'});
  }

  // Insert EME version number into initData
  if (fuzzed_data.ConsumeBool()) {
    initData.insert(initData.end(), {1, 0, 0, 0});
  }

  // Insert system ID into initData
  switch (fuzzed_data.ConsumeIntegral<uint8_t>() % 3) {
    case 0:
      initData.insert(initData.end(), {0x10, 0x77, 0xEF, 0xEC, 0xC0, 0xB2,
        0x4D, 0x02, 0xAC, 0xE3, 0x3C, 0x1E, 0x52, 0xE2, 0xFB, 0x4B});
      break;
    case 1:
      initData.insert(initData.end(), {0xE2, 0x71, 0x9D, 0x58, 0xA9, 0x85,
        0xB3, 0xC9, 0x78, 0x1A, 0xB0, 0x30, 0xAF, 0x78, 0xD3, 0x0E});
      break;
    default:
      break;
  }

  // Insert key ID count into initData as uint8_t's
  if (fuzzed_data.ConsumeBool()) {
    uint32_t keyIdBytes = initDataSize - initData.size() - 2*sizeof(uint32_t);
    uint32_t keyIdCount = htonl((keyIdBytes/16));
    pushUint32_t(initData, keyIdCount);
  }

  // Insert random uint8_t's into initData until full
  for (size_t i = initData.size(); i < initDataSize; i++) {
    initData.push_back(fuzzed_data.ConsumeIntegral<uint8_t>());
  }

  // Initialize mimeType parameter
  const std::string mimeTypeStrings[] = {"cenc", "audio/mp4", "video/mp4",
    "webm", "audio/webm", "video/webm", fuzzed_data.ConsumeBytesAsString(8)};
  const int numberOfMimeTypes = 7;
  const std::string mimeType = mimeTypeStrings[
    fuzzed_data.ConsumeIntegral<uint8_t>() % numberOfMimeTypes];

  // Initialize keyType parameter
  android::hardware::drm::V1_0::KeyType keyType;
  switch (fuzzed_data.ConsumeIntegral<uint8_t>() % 3) {
    case 0:
      keyType = android::hardware::drm::V1_0::KeyType::OFFLINE;
      break;
    case 1:
      keyType = android::hardware::drm::V1_0::KeyType::STREAMING;
      break;
    default:
      keyType = android::hardware::drm::V1_0::KeyType::RELEASE;
  }

  // Declare licenseRequest parameter and fill with uint8_t's
  std::vector<uint8_t> licenseRequest;
  uint16_t licenseRequestSize = fuzzed_data.ConsumeIntegral<uint16_t>();
  for (uint16_t i = 0; i < licenseRequestSize; ++i) {
    licenseRequest.push_back(fuzzed_data.ConsumeIntegral<uint8_t>());
  }

  parser.parse(initData, mimeType, keyType, &licenseRequest);

  return 0;
}

