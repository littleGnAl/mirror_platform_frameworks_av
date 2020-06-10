/*
 * Copyright 2020 The Android Open Source Project
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

#include <functional>
#include <string>
#include <vector>

#include <utils/String8.h>

#include "fuzzer/FuzzedDataProvider.h"
#include "mediautils/BatteryNotifier.h"

static constexpr int kMaxOperations = 30;
static constexpr int kMaxStringLength = 500;
using android::BatteryNotifier;

std::vector<std::function<void(std::string /*flashlight_name_str*/,
                               std::string /*camera_name_str*/,
                               uid_t /*video_uid*/, uid_t /*audio_uid*/,
                               uid_t /*light_uid*/, uid_t /*camera_uid*/)>>
    operations = {
        [](std::string, std::string, uid_t, uid_t, uid_t, uid_t) -> void {
          BatteryNotifier::getInstance().noteResetVideo();
        },
        [](std::string, std::string, uid_t, uid_t, uid_t, uid_t) -> void {
          BatteryNotifier::getInstance().noteResetAudio();
        },
        [](std::string, std::string, uid_t, uid_t, uid_t, uid_t) -> void {
          BatteryNotifier::getInstance().noteResetFlashlight();
        },
        [](std::string, std::string, uid_t, uid_t, uid_t, uid_t) -> void {
          BatteryNotifier::getInstance().noteResetCamera();
        },
        [](std::string, std::string, uid_t video_uid, uid_t, uid_t,
           uid_t) -> void {
          BatteryNotifier::getInstance().noteStartVideo(video_uid);
        },
        [](std::string, std::string, uid_t video_uid, uid_t, uid_t,
           uid_t) -> void {
          BatteryNotifier::getInstance().noteStopVideo(video_uid);
        },
        [](std::string, std::string, uid_t, uid_t audio_uid, uid_t,
           uid_t) -> void {
          BatteryNotifier::getInstance().noteStartAudio(audio_uid);
        },
        [](std::string, std::string, uid_t, uid_t audio_uid, uid_t,
           uid_t) -> void {
          BatteryNotifier::getInstance().noteStopAudio(audio_uid);
        },
        [](std::string flashlight_name_str, std::string, uid_t, uid_t,
           uid_t light_uid, uid_t) -> void {
          android::String8 name(flashlight_name_str.c_str());
          BatteryNotifier::getInstance().noteFlashlightOn(name, light_uid);
        },
        [](std::string flashlight_name_str, std::string, uid_t, uid_t,
           uid_t light_uid, uid_t) -> void {
          android::String8 name(flashlight_name_str.c_str());
          BatteryNotifier::getInstance().noteFlashlightOff(name, light_uid);
        },
        [](std::string, std::string camera_name_str, uid_t, uid_t, uid_t,
           uid_t camera_uid) -> void {
          android::String8 name(camera_name_str.c_str());
          BatteryNotifier::getInstance().noteStartCamera(name, camera_uid);
        },
        [](std::string, std::string camera_name_str, uid_t, uid_t, uid_t,
           uid_t camera_uid) -> void {
          android::String8 name(camera_name_str.c_str());
          BatteryNotifier::getInstance().noteStopCamera(name, camera_uid);
        },
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider data_provider(data, size);
    std::string camera_name =
        data_provider.ConsumeRandomLengthString(kMaxStringLength);
    std::string flashlight_name =
        data_provider.ConsumeRandomLengthString(kMaxStringLength);
    uid_t video_uid = data_provider.ConsumeIntegral<uid_t>();
    uid_t audio_uid = data_provider.ConsumeIntegral<uid_t>();
    uid_t light_uid = data_provider.ConsumeIntegral<uid_t>();
    uid_t camera_uid = data_provider.ConsumeIntegral<uid_t>();
    size_t ops_run = 0;
    while (data_provider.remaining_bytes() > 0 && ops_run++ < kMaxOperations) {
    uint8_t op =
          data_provider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
    operations[op](flashlight_name, camera_name, video_uid, audio_uid,
                   light_uid, camera_uid);
    }
    return 0;
}