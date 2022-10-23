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
#include <unordered_map>

#include <android-base/logging.h>
#include "BundleTypes.h"
#include "SessionContext.h"

namespace aidl::android::hardware::audio::effect {

/**
 * @brief Maintain all effect bundle sessions.
 *
 * Sessions are identified with the session ID, maximum of MAX_BUNDLE_SESSIONS is supported by the * bundle implementation.
 */
class GlobalSession {
  public:
    bool isSessionIdExist(const int& sessionId) { return mSessionMap.count(sessionId); }
    /**
     * Get the SessionContext in unique_ptr container if it exist, otherwise create one and return.
     */
    std::shared_ptr<SessionContext> getOrCreateSession(const BundleEffectType& type,
                                                       const Parameter::Common& common,
                                                       const Parameter::Specific& specific) {
        int id = common.session;
        if (mSessionMap.count(id)) {
            mSessionMap[id]->update(common, specific);
            return mSessionMap[id];
        } else {
            //auto& bundleContext = std::make_unique<::android::BundledEffectContext>();
            //auto& effectContext = std::make_unique<::android::SessionContext>();
            return mSessionMap[id] = std::make_shared<SessionContext>(type, common, specific);
        }
    }

  private:
    // Max session number supported.
    static constexpr int MAX_BUNDLE_SESSIONS = 32;
    std::unordered_map<int /* session ID */, std::shared_ptr<SessionContext>> mSessionMap;
};
}  // namespace aidl::android::hardware::audio::effect
