/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _NDK_MEDIA_CAS_PRIV_H
#define _NDK_MEDIA_CAS_PRIV_H

#include <mutex>
#include <thread>
#include <deque>
#include <condition_variable>

#include <android/hardware/cas/1.0/ICas.h>
#include <android/hardware/cas/1.0/ICasListener.h>
#include <android/hardware/cas/1.0/IMediaCasService.h>
#include <hidl/HidlSupport.h>

using namespace android;
using hardware::hidl_vec;
using hardware::Return;
using ::android::hardware::Void;
using namespace hardware::cas::V1_0;

struct AMediaCas {
  public:
    static bool isSystemIdSupported(const int32_t CA_system_id);
    static hidl_vec<HidlCasPluginDescriptor> enumeratePlugins();

    AMediaCas(const int32_t CA_system_id);
    ~AMediaCas();

    media_status_t setListener(AMediaCas_EventListener *listener);
    media_status_t setPrivateData(const AMediaCasData* privateData);
    media_status_t openSession(AMediaCasSessionId *sessionId);
    media_status_t closeSession(const AMediaCasSessionId* sessionId);
    media_status_t setSessionPrivateData(const AMediaCasSessionId* sessionId, const AMediaCasData* privateData);
    media_status_t processEcm(const AMediaCasSessionId* sessionId, const AMediaCasEcm* ecm);
    media_status_t processEmm(const AMediaCasEmm* emm);
    media_status_t sendEvent(int32_t event, int32_t arg, const AMediaCasData* eventData);
    media_status_t provision(const char* provisionString);
    media_status_t refreshEntitlements(int32_t refreshType, const AMediaCasData* refreshData);

    bool isValid() { return mValidity; }

  private:

    static sp<IMediaCasService> mCasService;

    struct CasEventMsg {
        int32_t event;
        int32_t arg;
        hidl_vec<uint8_t> data;
    };

    class BlockingQueue {
      public:
        void push(CasEventMsg const& value);
        CasEventMsg pop();
        int size();

      private:
        std::mutex              d_mutex;
        std::condition_variable d_condition;
        std::deque<CasEventMsg> d_queue;
    };

    sp<ICas> mCas;
    List<hidl_vec<uint8_t>> mIds;

    BlockingQueue mBlockingQueue;
    AMediaCas_EventListener* mListener;
    std::thread* mEventHandler;

    struct NdkMediaCasListener: public ICasListener {
      public:
        NdkMediaCasListener(AMediaCas* mediaCas) : mMediaCas(mediaCas) {};

        Return<void> onEvent(int32_t event, int32_t arg, const hidl_vec<uint8_t>& data) override;

      private:
        AMediaCas* mMediaCas;
    };
    sp<NdkMediaCasListener> mCasClient;

    void eventHandlerFct();
    bool findId(const AMediaCasByteArray &id, List<hidl_vec<uint8_t>>::iterator &iter);

    bool mValidity;
};

#endif // _NDK_MEDIA_CAS_PRIV_H