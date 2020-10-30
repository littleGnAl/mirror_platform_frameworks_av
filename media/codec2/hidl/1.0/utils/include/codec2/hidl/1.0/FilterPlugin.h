/*
 * Copyright 2018, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC2_HIDL_V1_0_UTILS_FILTER_PLUGIN_H

#define CODEC2_HIDL_V1_0_UTILS_FILTER_PLUGIN_H

#include <memory>

#include <C2Component.h>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

class FilterPlugin_V1 {
public:
    static constexpr int32_t VERSION = 1;

    virtual ~FilterPlugin_V1() = default;
    virtual std::shared_ptr<C2ComponentStore> getComponentStore() = 0;
};

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

extern "C" {

typedef int32_t (*GetFilterPluginVersionFunc)();
int32_t GetFilterPluginVersion();

typedef void* (*CreateFilterPluginFunc)();
void *CreateFilterPlugin();

typedef void (*DestroyFilterPluginFunc)(void *);
void DestroyFilterPlugin(void *plugin);

}  // extern "C"

#endif  // CODEC2_HIDL_V1_0_UTILS_FILTER_PLUGIN_H
