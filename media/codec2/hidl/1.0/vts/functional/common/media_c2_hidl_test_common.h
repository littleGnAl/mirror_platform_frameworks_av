/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef MEDIA_C2_HIDL_TEST_COMMON_H
#define MEDIA_C2_HIDL_TEST_COMMON_H

#include <C2Component.h>
#include <C2Config.h>

#include <codec2/hidl/client.h>
#include <getopt.h>
#include <gtest/gtest.h>
#include <hidl/HidlSupport.h>
#include <chrono>
#include <fstream>

#define FLAG_NON_DISPLAY_FRAME (1 << 4)
#define MAX_RETRY 20
#define TIME_OUT 400ms
#define MAX_INPUT_BUFFERS 8
#define FLUSH_INTERVAL 30

using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;

using namespace ::std::chrono;

static std::vector<std::tuple<std::string, std::string>> kTestParameters;

struct FrameInfo {
    int bytesCount;
    uint32_t flags;
    int64_t timestamp;
};

/*
 * Handle Callback functions onWorkDone(), onTripped(),
 * onError(), onDeath(), onFramesRendered()
 */
struct CodecListener : public android::Codec2Client::Listener {
  public:
    CodecListener(
            const std::function<void(std::list<std::unique_ptr<C2Work>>& workItems)> fn = nullptr)
        : callBack(fn) {}
    virtual void onWorkDone(const std::weak_ptr<android::Codec2Client::Component>& comp,
                            std::list<std::unique_ptr<C2Work>>& workItems) override {
        /* TODO */
        ALOGD("onWorkDone called");
        (void)comp;
        if (callBack) callBack(workItems);
    }

    virtual void onTripped(
            const std::weak_ptr<android::Codec2Client::Component>& comp,
            const std::vector<std::shared_ptr<C2SettingResult>>& settingResults) override {
        /* TODO */
        (void)comp;
        (void)settingResults;
    }

    virtual void onError(const std::weak_ptr<android::Codec2Client::Component>& comp,
                         uint32_t errorCode) override {
        /* TODO */
        (void)comp;
        ALOGD("onError called");
        if (errorCode != 0) ALOGE("Error : %u", errorCode);
    }

    virtual void onDeath(const std::weak_ptr<android::Codec2Client::Component>& comp) override {
        /* TODO */
        (void)comp;
    }

    virtual void onInputBufferDone(uint64_t frameIndex, size_t arrayIndex) override {
        /* TODO */
        (void)frameIndex;
        (void)arrayIndex;
    }

    virtual void onFrameRendered(uint64_t bufferQueueId, int32_t slotId,
                                 int64_t timestampNs) override {
        /* TODO */
        (void)bufferQueueId;
        (void)slotId;
        (void)timestampNs;
    }
    // std::mutex mQueueLock;
    // std::condition_variable mQueueCondition;
    // std::list<std::unique_ptr<C2Work>> mWorkQueue;
    std::function<void(std::list<std::unique_ptr<C2Work>>& workItems)> callBack;
};

// Return all test parameters, a list of tuple of <instance, component>.
const std::vector<std::tuple<std::string, std::string>>& getTestParameters();

<<<<<<< HEAD   (39f57f Merge "Merge "extractors: allow OEM to control output type f)
// Return all test parameters, a list of tuple of <instance, component> with matching domain and
// kind.
const std::vector<std::tuple<std::string, std::string>>& getTestParameters(
        C2Component::domain_t domain, C2Component::kind_t kind);
=======
   public:
    virtual void registerTestServices() override {
        registerTestService<IComponentStore>();
    }

    ComponentTestEnvironment() : res("/data/local/tmp/media/") {}

    void setComponent(const char* _component) { component = _component; }

    void setInstance(const char* _instance) { instance = _instance; }

    void setRes(const char* _res) { res = _res; }

    const hidl_string getInstance() const { return instance; }

    const hidl_string getComponent() const { return component; }

    const hidl_string getRes() const { return res; }

    int initFromOptions(int argc, char** argv) {
        static struct option options[] = {
            {"instance", required_argument, 0, 'I'},
            {"component", required_argument, 0, 'C'},
            {"res", required_argument, 0, 'P'},
            {0, 0, 0, 0}};

        while (true) {
            int index = 0;
            int c = getopt_long(argc, argv, "I:C:P:", options, &index);
            if (c == -1) {
                break;
            }

            switch (c) {
                case 'I':
                    setInstance(optarg);
                    break;
                case 'C':
                    setComponent(optarg);
                    break;
                case 'P':
                    setRes(optarg);
                    break;
                case '?':
                    break;
            }
        }

        if (optind < argc) {
            fprintf(stderr,
                    "unrecognized option: %s\n\n"
                    "usage: %s <gtest options> <test options>\n\n"
                    "test options are:\n\n"
                    "-I, --instance: software for C2 components, else default\n"
                    "-C, --component: C2 component to test\n"
                    "-P, --res: Resource files directory location\n",
                    argv[optind ?: 1], argv[0]);
            return 2;
        }
        return 0;
    }

   private:
    hidl_string instance;
    hidl_string component;
    hidl_string res;
};
>>>>>>> BRANCH (e788c2 Merge "Codec2 VTS: Move device resource files to data/local/)

/*
 * common functions declarations
 */
void testInputBuffer(const std::shared_ptr<android::Codec2Client::Component>& component,
                     std::mutex& queueLock, std::list<std::unique_ptr<C2Work>>& workQueue,
                     uint32_t flags, bool isNullBuffer);

void waitOnInputConsumption(std::mutex& queueLock, std::condition_variable& queueCondition,
                            std::list<std::unique_ptr<C2Work>>& workQueue,
                            size_t bufferCount = MAX_INPUT_BUFFERS);

void workDone(const std::shared_ptr<android::Codec2Client::Component>& component,
              std::unique_ptr<C2Work>& work, std::list<uint64_t>& flushedIndices,
              std::mutex& queueLock, std::condition_variable& queueCondition,
              std::list<std::unique_ptr<C2Work>>& workQueue, bool& eos, bool& csd,
              uint32_t& framesReceived);

int64_t getNowUs();

int32_t populateInfoVector(std::string info, android::Vector<FrameInfo>* frameInfo,
                           bool timestampDevTest, std::list<uint64_t>* timestampUslist);

void verifyFlushOutput(std::list<std::unique_ptr<C2Work>>& flushedWork,
                       std::list<std::unique_ptr<C2Work>>& workQueue,
                       std::list<uint64_t>& flushedIndices, std::mutex& queueLock);
#endif  // MEDIA_C2_HIDL_TEST_COMMON_H
