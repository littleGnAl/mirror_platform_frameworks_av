/*
 * Copyright (C) 2023 The Android Open Source Project
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

#define LOG_TAG "EffectFactoryServiceFuzzer"
// #define LOG_NDEBUG 0

#include <aidl/android/hardware/audio/effect/IFactory.h>
#include <android/binder_manager.h>

#include "fuzzer/FuzzedDataProvider.h"

using ::aidl::android::hardware::audio::effect::IFactory;

class EffectFactoryFuzzer {
   public:
     EffectFactoryFuzzer(std::shared_ptr<IFactory> factory,
                         std::shared_ptr<FuzzedDataProvider> dataProvider)
         : mIFactory(std::move(factory)), mFuzzedDataProvider(std::move(dataProvider)) {}

     ~EffectFactoryFuzzer() {}
     void process();

   private:
     const std::shared_ptr<IFactory> mIFactory;
     const std::shared_ptr<FuzzedDataProvider> mFuzzedDataProvider;
};

void EffectFactoryFuzzer::process() {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    std::shared_ptr<FuzzedDataProvider> dataProvider = std::make_shared<FuzzedDataProvider>(data, size);

    auto serviceName = std::string(IFactory::descriptor) + "/default";
    auto service = IFactory::fromBinder(
            ndk::SpAIBinder(AServiceManager_waitForService(serviceName.c_str())));
    if (!service) {
        ALOGE("%s binder service %s not exist", __func__, serviceName.c_str());
        return -1;
    }

    auto fuzzer = std::make_shared<EffectFactoryFuzzer>(service, dataProvider);
    if (!fuzzer) {
        return -2;
    }
    fuzzer->process();
    return 0;
}