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

#include "fuzzer/FuzzedDataProvider.h"
#include <MediaAnalyticsService.h>
//#include <binder/Parcel.h>
#include <media/MediaAnalyticsItem.h>
#include <memory>
#include <stdio.h>
#include <utils/Errors.h>

using namespace android;

const size_t max_str_length = 100;
const size_t max_att_count = 10;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size) {
  if (size < 10)
    return 0;

  FuzzedDataProvider data_provider(bytes, size);

  auto service = std::make_unique<MediaAnalyticsService>();

  // the API use caller uid to determine if caller is trusted,
  // if the caller is not trusted, only allowedKey will trigger further logic.
  // as we haven't mock the uid getter API, we use allowedKeys in half of data
  // to accelerate coverage increasing.
  std::string allowedKeys[] = {
      "audiopolicy", "audiorecord", "audiothread", "audiotrack",
      "codec",       "extractor",   "nuplayer",
  };
  bool useAllowedKeys = data_provider.ConsumeBool();
  std::string key;
  if (useAllowedKeys) {
    key = allowedKeys[data_provider.ConsumeIntegralInRange<int32_t>(0, 6)];
  } else {
    key = data_provider.ConsumeRandomLengthString(max_str_length);
  }
  
  auto item = MediaAnalyticsItem::create(key);

  // the API actually discard these data for untrusted caller
  int32_t pid = data_provider.ConsumeIntegral<int32_t>();
  item->setPid(pid);
  int32_t uid = data_provider.ConsumeIntegral<int32_t>();
  item->setUid(uid);

  std::string pkgName = data_provider.ConsumeRandomLengthString(max_str_length);
  item->setPkgName(pkgName);
  int64_t pkgVersionCode = data_provider.ConsumeIntegral<int64_t>();
  item->setPkgVersionCode(pkgVersionCode);
  int64_t sessionID = data_provider.ConsumeIntegral<int64_t>();
  item->setSessionID(sessionID);

  int64_t timestamp = data_provider.ConsumeIntegral<int64_t>();
  item->setTimestamp(timestamp);

  int count = data_provider.ConsumeIntegralInRange<int32_t>(0, max_att_count);
  for (int i = 0; i < count; i++) {
    std::string attr = data_provider.ConsumeRandomLengthString(max_str_length);
    int32_t ztype = data_provider.ConsumeIntegralInRange<int32_t>(1, 5);
    switch (ztype) {
    case MediaAnalyticsItem::kTypeInt32:
      item->setInt32(attr.c_str(), data_provider.ConsumeIntegral<int32_t>());
      break;
    case MediaAnalyticsItem::kTypeInt64:
      item->setInt64(attr.c_str(), data_provider.ConsumeIntegral<int64_t>());
      break;
    case MediaAnalyticsItem::kTypeDouble:
      item->setDouble(attr.c_str(),
                      data_provider.ConsumeFloatingPoint<double>());
      break;
    case MediaAnalyticsItem::kTypeCString: {
      std::string attr_str =
          data_provider.ConsumeRandomLengthString(max_str_length);
      item->setCString(attr.c_str(), attr_str.c_str());
    } break;
    case MediaAnalyticsItem::kTypeRate: {
      int64_t count = data_provider.ConsumeIntegral<int64_t>();
      int64_t duration = data_provider.ConsumeIntegral<int64_t>();
      item->setRate(attr.c_str(), count, duration);
    } break;
    default:
      return 0;
    }
  }

  bool forcenew = data_provider.ConsumeBool();

  // the api should be called by binder,
  // it is a reasonable idea to write it to parcel then read back, simulating binder logic,
  // but readFromParcel always terminates fuzzer without a crash
  // Parcel parcel;
  // if (item->writeToParcel(&parcel) < 0)
  //  return 0;
  // if (item->readFromParcel(parcel) < 0)
  //  return 0;

  // TO DO: the API uses IPCThreadState::self()->getCallingUid() to determine
  // whether caller is trusted. Is is a good idea to mock that?
  // also, is it a better idea to call the API multiple times?
  service->submit(item, forcenew);
  return 0;
}