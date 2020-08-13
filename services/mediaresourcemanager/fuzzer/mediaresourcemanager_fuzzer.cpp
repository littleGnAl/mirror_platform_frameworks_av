/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */

#include <ServiceLog.h>
#include <aidl/android/media/BnResourceManagerClient.h>
#include <media/MediaResource.h>
#include <media/MediaResourcePolicy.h>
#include <media/stagefright/ProcessInfoInterface.h>
#include <media/stagefright/foundation/ADebug.h>
#include "ResourceManagerService.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace android;
using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::BnResourceManagerClient;
using ::aidl::android::media::IResourceManagerClient;
using ::aidl::android::media::IResourceManagerService;
using MedResType = aidl::android::media::MediaResourceType;
using MedResSubType = aidl::android::media::MediaResourceSubType;

const size_t kMaxStringLength = 100;
const int32_t kMaxServiceLog = 100;
const int32_t kMinServiceLog = 1;
const int32_t kMinResources = 1;
const int32_t kMaxResources = 10;
const int32_t kMinResourceType = 0;
const int32_t kMaxResourceType = 10;
const std::string kPolicyType[] = {
    IResourceManagerService::kPolicySupportsMultipleSecureCodecs,
    IResourceManagerService::kPolicySupportsSecureWithNonSecureCodec};

static int64_t getId(const std::shared_ptr<IResourceManagerClient>& client) {
    return (int64_t)client.get();
}

struct TestProcessInfo : public ProcessInfoInterface {
    TestProcessInfo() {}
    virtual ~TestProcessInfo() {}

    virtual bool getPriority(int pid, int* priority) {
        // For testing, use pid as priority.
        // Lower the value higher the priority.
        *priority = pid;
        return true;
    }

    virtual bool isValidPid(int /* pid */) { return true; }
    virtual bool overrideProcessInfo(int /* pid */, int /*procState*/, int /*oomScore*/) {
        return true;
    }
    virtual void removeProcessInfoOverride(int /* pid */) { return; }

   private:
    DISALLOW_EVIL_CONSTRUCTORS(TestProcessInfo);
};

struct TestSystemCallback : public ResourceManagerService::SystemCallbackInterface {
    TestSystemCallback() : mLastEvent({EventType::INVALID, 0}), mEventCount(0) {}

    enum EventType {
        INVALID = -1,
        VIDEO_ON = 0,
        VIDEO_OFF = 1,
        VIDEO_RESET = 2,
        CPUSET_ENABLE = 3,
        CPUSET_DISABLE = 4,
    };

    struct EventEntry {
        EventType type;
        int arg;
    };

    virtual void noteStartVideo(int uid) override {
        mLastEvent = {EventType::VIDEO_ON, uid};
        ++mEventCount;
    }

    virtual void noteStopVideo(int uid) override {
        mLastEvent = {EventType::VIDEO_OFF, uid};
        ++mEventCount;
    }

    virtual void noteResetVideo() override {
        mLastEvent = {EventType::VIDEO_RESET, 0};
        ++mEventCount;
    }

    virtual bool requestCpusetBoost(bool enable) override {
        mLastEvent = {enable ? EventType::CPUSET_ENABLE : EventType::CPUSET_DISABLE, 0};
        ++mEventCount;
        return true;
    }

    size_t eventCount() { return mEventCount; }
    EventType lastEventType() { return mLastEvent.type; }
    EventEntry lastEvent() { return mLastEvent; }

   protected:
    virtual ~TestSystemCallback() {}

   private:
    EventEntry mLastEvent;
    size_t mEventCount;

    DISALLOW_EVIL_CONSTRUCTORS(TestSystemCallback);
};

struct TestClient : public BnResourceManagerClient {
    TestClient(int pid, const std::shared_ptr<ResourceManagerService>& service)
        : mReclaimed(false), mPid(pid), mService(service) {}

    Status reclaimResource(bool* aidlReturn) override {
        mService->removeClient(mPid, getId(ref<TestClient>()));
        mReclaimed = true;
        *aidlReturn = true;
        return Status::ok();
    }

    Status getName(::std::string* aidlReturn) override {
        *aidlReturn = "test_client";
        return Status::ok();
    }

    virtual ~TestClient() {}

   private:
    bool mReclaimed;
    int mPid;
    std::shared_ptr<ResourceManagerService> mService;
    DISALLOW_EVIL_CONSTRUCTORS(TestClient);
};

class ResourceManagerServiceFuzzer {
   public:
    ResourceManagerServiceFuzzer() = default;
    ~ResourceManagerServiceFuzzer() {
        mService = nullptr;
        delete mFuzzedDataProvider;
    }
    void process(const uint8_t* data, size_t size);

   private:
    void setConfig();
    void setResources();
    void setServiceLog();

    std::shared_ptr<ResourceManagerService> mService =
        ::ndk::SharedRefBase::make<ResourceManagerService>(new TestProcessInfo(),
                                                           new TestSystemCallback());
    FuzzedDataProvider* mFuzzedDataProvider = nullptr;
};

void ResourceManagerServiceFuzzer::process(const uint8_t* data, size_t size) {
    mFuzzedDataProvider = new FuzzedDataProvider(data, size);
    setConfig();
    setResources();
    setServiceLog();
}

void ResourceManagerServiceFuzzer::setConfig() {
    bool policyTypeIndex = mFuzzedDataProvider->ConsumeBool();
    std::string policyValue = mFuzzedDataProvider->ConsumeRandomLengthString(kMaxStringLength);
    if (mService) {
        std::vector<MediaResourcePolicyParcel> policies;
        policies.push_back(MediaResourcePolicy(kPolicyType[policyTypeIndex], policyValue));
        mService->config(policies);
    }
}

void ResourceManagerServiceFuzzer::setResources() {
    int32_t mediaResourceType =
        mFuzzedDataProvider->ConsumeIntegralInRange<int32_t>(kMinResourceType, kMaxResourceType);
    int32_t mediaResourceSubType =
        mFuzzedDataProvider->ConsumeIntegralInRange<int32_t>(kMinResourceType, kMaxResourceType);
    uint64_t mediaResourceValue = mFuzzedDataProvider->ConsumeIntegral<uint64_t>();
    size_t maxResources =
        mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(kMinResources, kMaxResources);
    int32_t pid = mFuzzedDataProvider->ConsumeIntegral<int32_t>();
    int32_t uid = mFuzzedDataProvider->ConsumeIntegral<int32_t>();
    int32_t pidZero = 0;

    if (mService) {
        std::shared_ptr<IResourceManagerClient> testClient =
            ::ndk::SharedRefBase::make<TestClient>(pid, mService);
        std::vector<MediaResourceParcel> mediaRes;
        bool result;
        for (size_t i = 0; i < maxResources; ++i) {
            mediaRes.push_back(MediaResource(static_cast<MedResType>(mediaResourceType),
                                             static_cast<MedResSubType>(mediaResourceSubType),
                                             mediaResourceValue));
            mService->addResource(pid, uid, getId(testClient), testClient, mediaRes);
        }

        mService->markClientForPendingRemoval(pid, getId(testClient));
        bool shouldRemoveClientFirst = mFuzzedDataProvider->ConsumeBool();
        bool shouldRemoveResourceFirst = mFuzzedDataProvider->ConsumeBool();

        if (shouldRemoveClientFirst) {
            mService->removeClient(pid, getId(testClient));
            mService->reclaimResource(pid, mediaRes, &result);
            mService->removeResource(pid, getId(testClient), mediaRes);
        } else if (shouldRemoveResourceFirst) {
            mService->removeResource(pid, getId(testClient), mediaRes);
            mService->reclaimResource(pid, mediaRes, &result);
            mService->removeClient(pid, getId(testClient));
        } else {
            mService->reclaimResource(pid, mediaRes, &result);
            mService->removeResource(pid, getId(testClient), mediaRes);
            mService->removeClient(pid, getId(testClient));
        }

        // No resource was added with pid = 0
        mService->reclaimResource(pidZero, mediaRes, &result);
        mService->removeResource(pidZero, getId(testClient), mediaRes);
        mService->removeClient(pidZero, getId(testClient));

        mService->overridePid(pid, pid - 1);
    }
}

void ResourceManagerServiceFuzzer::setServiceLog() {
    size_t maxNum =
        mFuzzedDataProvider->ConsumeIntegralInRange<int32_t>(kMinServiceLog, kMaxServiceLog);
    sp<ServiceLog> serviceLog = new ServiceLog(maxNum);
    if (serviceLog) {
        serviceLog->add(String8("log"));
        serviceLog->toString();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return 0;
    }
    ResourceManagerServiceFuzzer* rmFuzzer = new ResourceManagerServiceFuzzer();
    if (!rmFuzzer) {
        return 0;
    }
    rmFuzzer->process(data, size);
    delete rmFuzzer;
    return 0;
}
