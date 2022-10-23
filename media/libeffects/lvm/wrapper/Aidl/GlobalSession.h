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
#include "BundleContext.h"

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
     * Get the BundleContext in unique_ptr container if it exist, otherwise create one and return.
     */
    std::shared_ptr<BundleContext> getOrCreateSession(const BundleEffectType& type,
                                                      const int& sessionId) {
        LOG(DEBUG) << __func__ << type << " with sessionId " << sessionId;
        if (mSessionMap.count(sessionId)) {
            mSessionMap[sessionId]->update(type);
            return mSessionMap[sessionId];
        } else {
            if (mSessionMap.size() >= MAX_BUNDLE_SESSIONS) {
                LOG(ERROR) << __func__ << " exceed max bundle session";
                return nullptr;
            }

            auto context = std::make_shared<BundleContext>(sessionId, type);
            RetCode ret = context->init();
            if (RetCode::SUCCESS != ret) {
                LOG(ERROR) << __func__ << " context init ret " << ret;
                return nullptr;
            }
            return context;
        }
    }

    void releaseSession(const int& sessionId) {
        LOG(DEBUG) << __func__ << " sessionId " << sessionId;
        if (mSessionMap.count(sessionId)) {
            mSessionMap[sessionId]->deInit();
            mSessionMap.erase(sessionId);
        }
    }

  private:
    // Max session number supported.
    static constexpr int MAX_BUNDLE_SESSIONS = 32;
    std::unordered_map<int /* session ID */, std::shared_ptr<BundleContext>> mSessionMap;
};
}  // namespace aidl::android::hardware::audio::effect
