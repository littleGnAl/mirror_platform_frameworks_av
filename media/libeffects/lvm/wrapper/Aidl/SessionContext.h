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

#pragma once
#include <memory>
#include <vector>
#include <android-base/logging.h>

#include "BundleContext.h"
#include "BundleTypes.h"

namespace aidl::android::hardware::audio::effect {

class SessionContext {
  public:
    SessionContext(const BundleEffectType& type, const Parameter::Common& common,
                   const Parameter::Specific& specific)
        : mEnablement(false) {
        LOG(DEBUG) << __func__ << type << common.toString();
        mBundleContext = std::make_shared<BundleContext>(common, specific);
        setType(type);
    }
    ~SessionContext() { LOG(DEBUG) << __func__ << mType << " enablement " << mEnablement; }

    void enable() { mEnablement = true; }
    void disable() { mEnablement = false; }
    void setType(BundleEffectType type) { mType = type; }
    void update(const Parameter::Common& common, const Parameter::Specific& specific) {
        mBundleContext->update(common, specific);
    }

  private:
    bool mEnablement = false;
    BundleEffectType mType;
    std::shared_ptr<BundleContext> mBundleContext;
};
}  // namespace aidl::android::hardware::audio::effect

