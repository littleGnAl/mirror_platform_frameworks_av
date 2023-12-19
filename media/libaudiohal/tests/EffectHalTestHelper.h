/*
 * Copyright 2024 The Android Open Source Project
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

#pragma once

#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <media/AidlConversionCppNdk.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <system/audio_aidl_utils.h>
#include <system/audio_effect.h>
#include <system/audio_effects/audio_effects_utils.h>

namespace android {

// using ::android::audio::utils::toString;
using effect::utils::EffectParamReader;
using effect::utils::EffectParamWriter;

class EffectHalTestHelper {
  public:
    template <typename P, typename V>
    std::shared_ptr<EffectParamReader> createEffectParam(const P& p, const V& v, size_t len) {
        mBuffer.resize(sizeof(effect_param_t) + sizeof(p) + sizeof(v) + 4);
        effect_param_t* param = (effect_param_t*)(mBuffer.data());
        param->psize = sizeof(P);
        param->vsize = sizeof(V);

        EffectParamWriter writer(*param);
        EXPECT_EQ(OK, writer.writeToParameter(&p));
        EXPECT_EQ(OK, writer.writeToValue(&v));
        writer.finishValueWrite();
        mVSize = len;
        mParam = std::make_shared<EffectParamReader>(writer);
        return mParam;
    }

  private:
    std::vector<uint8_t> mBuffer;
    std::shared_ptr<EffectParamReader> mParam;
    size_t mVSize;
};

}  // namespace android
