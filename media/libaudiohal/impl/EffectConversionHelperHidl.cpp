/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "HalHidl"
#include <utils/Log.h>

#include "EffectConversionHelperHidl.h"

namespace android {

EffectConversionHelperHidl::EffectConversionHelperHidl(std::string_view className)
        : ConversionHelperHidl<EffectResult>(className, analyzeResult) {
}

// static
status_t EffectConversionHelperHidl::analyzeResult(const EffectResult& result) {
    switch (result) {
        case EffectResult::OK: return OK;
        case EffectResult::INVALID_ARGUMENTS: return BAD_VALUE;
        case EffectResult::INVALID_STATE: return NOT_ENOUGH_DATA;
        case EffectResult::NOT_INITIALIZED: return NO_INIT;
        case EffectResult::NOT_SUPPORTED: return INVALID_OPERATION;
        case EffectResult::RESULT_TOO_BIG: return NO_MEMORY;
    }
    return NO_INIT;
}

}  // namespace android
