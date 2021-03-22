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

// #define LOG_NDEBUG 0
#define LOG_TAG "media_c2_hidl_test_common"
#include <stdio.h>
#include <algorithm>

#include "media_c2_hidl_test_common.h"

#include <android/hardware/media/c2/1.0/IComponentStore.h>
#include <media/NdkMediaExtractor.h>

// Test the codecs for NullBuffer, Empty Input Buffer with(out) flags set
void testInputBuffer(const std::shared_ptr<android::Codec2Client::Component>& component,
                     std::mutex& queueLock, std::list<std::unique_ptr<C2Work>>& workQueue,
                     uint32_t flags, bool isNullBuffer) {
    std::unique_ptr<C2Work> work;
    {
        typedef std::unique_lock<std::mutex> ULock;
        ULock l(queueLock);
        if (!workQueue.empty()) {
            work.swap(workQueue.front());
            workQueue.pop_front();
        } else {
            ASSERT_TRUE(false) << "workQueue Empty at the start of test";
        }
    }
    ASSERT_NE(work, nullptr);

    work->input.flags = (C2FrameData::flags_t)flags;
    work->input.ordinal.timestamp = 0;
    work->input.ordinal.frameIndex = 0;
    work->input.buffers.clear();
    if (isNullBuffer) {
        work->input.buffers.emplace_back(nullptr);
    }
    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);

    std::list<std::unique_ptr<C2Work>> items;
    items.push_back(std::move(work));
    ASSERT_EQ(component->queue(&items), C2_OK);
}

// Wait for all the inputs to be consumed by the plugin.
void waitOnInputConsumption(std::mutex& queueLock, std::condition_variable& queueCondition,
                            std::list<std::unique_ptr<C2Work>>& workQueue, size_t bufferCount) {
    typedef std::unique_lock<std::mutex> ULock;
    uint32_t queueSize;
    uint32_t maxRetry = 0;
    {
        ULock l(queueLock);
        queueSize = workQueue.size();
    }
    while ((maxRetry < MAX_RETRY) && (queueSize < bufferCount)) {
        ULock l(queueLock);
        if (queueSize != workQueue.size()) {
            queueSize = workQueue.size();
            maxRetry = 0;
        } else {
            queueCondition.wait_for(l, TIME_OUT);
            maxRetry++;
        }
    }
}

// process onWorkDone received by Listener
void workDone(const std::shared_ptr<android::Codec2Client::Component>& component,
              std::unique_ptr<C2Work>& work, std::list<uint64_t>& flushedIndices,
              std::mutex& queueLock, std::condition_variable& queueCondition,
              std::list<std::unique_ptr<C2Work>>& workQueue, bool& eos, bool& csd,
              uint32_t& framesReceived) {
    // handle configuration changes in work done
    if (work->worklets.front()->output.configUpdate.size() != 0) {
        ALOGV("Config Update");
        std::vector<std::unique_ptr<C2Param>> updates =
                std::move(work->worklets.front()->output.configUpdate);
        std::vector<C2Param*> configParam;
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        for (size_t i = 0; i < updates.size(); ++i) {
            C2Param* param = updates[i].get();
            if (param->index() == C2StreamInitDataInfo::output::PARAM_TYPE) {
                C2StreamInitDataInfo::output* csdBuffer =
                        (C2StreamInitDataInfo::output*)(param);
                size_t csdSize = csdBuffer->flexCount();
                if (csdSize > 0) csd = true;
            } else if ((param->index() == C2StreamSampleRateInfo::output::PARAM_TYPE) ||
                       (param->index() == C2StreamChannelCountInfo::output::PARAM_TYPE) ||
                       (param->index() == C2StreamPictureSizeInfo::output::PARAM_TYPE)) {
                configParam.push_back(param);
            }
        }
        component->config(configParam, C2_DONT_BLOCK, &failures);
        ASSERT_EQ(failures.size(), 0u);
    }
    if (work->worklets.front()->output.flags != C2FrameData::FLAG_INCOMPLETE) {
        framesReceived++;
        eos = (work->worklets.front()->output.flags & C2FrameData::FLAG_END_OF_STREAM) != 0;
        auto frameIndexIt = std::find(flushedIndices.begin(), flushedIndices.end(),
                                      work->input.ordinal.frameIndex.peeku());
        ALOGV("WorkDone: frameID received %d",
              (int)work->worklets.front()->output.ordinal.frameIndex.peeku());
        work->input.buffers.clear();
        work->worklets.clear();
        {
            typedef std::unique_lock<std::mutex> ULock;
            ULock l(queueLock);
            workQueue.push_back(std::move(work));
            if (!flushedIndices.empty() &&
                (frameIndexIt != flushedIndices.end())) {
                flushedIndices.erase(frameIndexIt);
            }
            queueCondition.notify_all();
        }
    }
}

// Return current time in micro seconds
int64_t getNowUs() {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return (int64_t)tv.tv_usec + tv.tv_sec * 1000000ll;
}

// Return all test parameters, a list of tuple of <instance, component>
const std::vector<std::tuple<std::string, std::string>>& getTestParameters() {
    return getTestParameters(C2Component::DOMAIN_OTHER, C2Component::KIND_OTHER);
}

// Return all test parameters, a list of tuple of <instance, component> with matching domain and
// kind.
const std::vector<std::tuple<std::string, std::string>>& getTestParameters(
        C2Component::domain_t domain, C2Component::kind_t kind) {
    static std::vector<std::tuple<std::string, std::string>> parameters;

    auto instances = android::Codec2Client::GetServiceNames();
    for (std::string instance : instances) {
        std::shared_ptr<android::Codec2Client> client =
                android::Codec2Client::CreateFromService(instance.c_str());
        std::vector<C2Component::Traits> components = client->listComponents();
        for (C2Component::Traits traits : components) {
            if (instance.compare(traits.owner)) continue;
            if (domain != C2Component::DOMAIN_OTHER &&
                (traits.domain != domain || traits.kind != kind)) {
                continue;
            }

            parameters.push_back(std::make_tuple(instance, traits.name));
        }
    }

    return parameters;
}

// Populate Info vector and return number of CSDs
int32_t populateInfoVector(std::string info, android::Vector<FrameInfo>* frameInfo,
                           bool timestampDevTest, std::list<uint64_t>* timestampUslist) {
    std::ifstream eleInfo;
    eleInfo.open(info);
    if (!eleInfo.is_open()) {
        ALOGE("Can't open info file");
        return -1;
    }
    int32_t numCsds = 0;
    int32_t bytesCount = 0;
    uint32_t flags = 0;
    uint32_t timestamp = 0;
    while (1) {
        if (!(eleInfo >> bytesCount)) break;
        eleInfo >> flags;
        eleInfo >> timestamp;
        bool codecConfig = flags ? ((1 << (flags - 1)) & C2FrameData::FLAG_CODEC_CONFIG) != 0 : 0;
        if (codecConfig) numCsds++;
        bool nonDisplayFrame = ((flags & FLAG_NON_DISPLAY_FRAME) != 0);
        if (timestampDevTest && !codecConfig && !nonDisplayFrame) {
            timestampUslist->push_back(timestamp);
        }
        frameInfo->push_back({bytesCount, flags, timestamp});
    }
    ALOGV("numCsds : %d", numCsds);
    eleInfo.close();
    return numCsds;
}

void verifyFlushOutput(std::list<std::unique_ptr<C2Work>>& flushedWork,
                       std::list<std::unique_ptr<C2Work>>& workQueue,
                       std::list<uint64_t>& flushedIndices, std::mutex& queueLock) {
    // Update mFlushedIndices based on the index received from flush()
    typedef std::unique_lock<std::mutex> ULock;
    uint64_t frameIndex;
    ULock l(queueLock);
    for (std::unique_ptr<C2Work>& work : flushedWork) {
        ASSERT_NE(work, nullptr);
        frameIndex = work->input.ordinal.frameIndex.peeku();
        std::list<uint64_t>::iterator frameIndexIt =
                std::find(flushedIndices.begin(), flushedIndices.end(), frameIndex);
        if (!flushedIndices.empty() && (frameIndexIt != flushedIndices.end())) {
            flushedIndices.erase(frameIndexIt);
            work->input.buffers.clear();
            work->worklets.clear();
            workQueue.push_back(std::move(work));
        }
    }
    ASSERT_EQ(flushedIndices.empty(), true);
    flushedWork.clear();
}

int32_t extractBitstreamAndInfoFile(std::string inputFile, std::string extractedBitstream,
                                    std::string infoFile, char* mimeType) {
    FILE* inputFp = fopen(inputFile.c_str(), "rb");
    if (inputFp == nullptr) {
        std::cout << "[   WARN   ] Unable to open input file, skipping test.\n";
        return 0;
    }

    std::ofstream eleStream;
    eleStream.open(extractedBitstream.c_str(), std::ofstream::binary | std::ofstream::out);
    if (eleStream.is_open() != true) {
        ALOGE("unable to create temp file for dumping elementary stream");
        return -1;
    }

    std::ofstream eleInfo;
    eleInfo.open(infoFile.c_str(), std::ofstream::out);
    if (eleInfo.is_open() != true) {
        ALOGE( "unable to create temp info file");
        return -1;
    }

    // Read file properties
    struct stat buf;
    stat(inputFile.c_str(), &buf);
    size_t fileSize = buf.st_size;
    int32_t fd = fileno(inputFp);

    AMediaExtractor* extractor = AMediaExtractor_new();
    if (extractor == nullptr) {
        ALOGE("extractor creation failed");
        return -1;
    }

    media_status_t status = AMediaExtractor_setDataSourceFd(extractor, fd, 0, fileSize);
    if (status != AMEDIA_OK) {
        ALOGE("set datasource failed for extractor");
        return -1;
    }

    int32_t trackCount = AMediaExtractor_getTrackCount(extractor);
    if (trackCount > 1) {
        ALOGW("multi track inputs are not supported yet. Using 0th track");
    }

    AMediaFormat* format = AMediaExtractor_getTrackFormat(extractor, 0);
    if (format == nullptr) {
        ALOGE("Input file has no format");
        return -1;
    }

    AMediaExtractor_selectTrack(extractor, 0);

    const char* mime = nullptr;
    if (!AMediaFormat_getString(format, AMEDIAFORMAT_KEY_MIME, &mime)) {
        ALOGE("Failed to get mime from input file");
        AMediaFormat_delete(format);
        AMediaExtractor_delete(extractor);
        fclose(inputFp);
        return -1;
    }

    strcpy(mimeType, mime);

    int64_t timeStamp = 0;
    int32_t csdIndex = 0;
    std::string info;
    while (1) {
        size_t size = 0;
        char csdName[100];
        void* csdBuffer = nullptr;
        snprintf(csdName, sizeof(csdName), "csd-%d", csdIndex);
        bool csdFound = AMediaFormat_getBuffer(format, csdName, &csdBuffer, &size);
        if (csdFound) {
            // bitstream write
            eleStream.write((char*)csdBuffer, size);
            // info file write
            info = std::to_string(size) + " " + std::to_string(kCsdFlag) + " " +
                   std::to_string(timeStamp) + "\n";
            eleInfo << info;
            csdIndex++;
        } else break;
    }

    int32_t bufferSize = 0;
    if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_MAX_INPUT_SIZE, &bufferSize)) {
        bufferSize = kMaxBufferSize;
    }
    AMediaFormat_delete(format);

    std::vector<uint8_t> frameBuf(bufferSize);
    uint32_t flag = 0;
    ssize_t size = 0;
    int32_t frameId = 0;
    while (1) {
        size = AMediaExtractor_readSampleData(extractor, frameBuf.data(), bufferSize);
        if (size <= 0) break;
        // First frame after CSD for decoders is a SYNC Frame
        flag = frameId == 0 ? AMEDIAEXTRACTOR_SAMPLE_FLAG_SYNC
                            : AMediaExtractor_getSampleFlags(extractor);
        timeStamp = AMediaExtractor_getSampleTime(extractor);
        AMediaExtractor_advance(extractor);
        // bitstream write
        eleStream.write((char*)frameBuf.data(), size);
        // info file write
        info = std::to_string(size) + " " + std::to_string(flag) + " " + std::to_string(timeStamp) +
               "\n";
        eleInfo << info;
        frameId++;
    }
    AMediaExtractor_delete(extractor);

    fclose(inputFp);
    eleStream.close();
    eleInfo.close();
    return 0;
}

// returns number of entries for a given mime
int32_t getNumTestEntries(std::string mime, std::vector<CompToURL> lookUpTable) {
    int32_t streamCount = 0;
    for (size_t i = 0; i < lookUpTable.size(); ++i) {
        if (mime.find(lookUpTable[i].mime) != std::string::npos) {
            streamCount++;
        }
    }
    return streamCount;
}

void addCustomTestParamsFromFile(std::string filePath, std::vector<CompToURL> lookUpTable) {
    std::ifstream infile(filePath);
    if (infile.is_open() == true) {
        std::string line = "";
        static std::string externalInput = "";
        static std::string externalChecksum = "";
        while (std::getline(infile, line)) {
            std::istringstream inputString(line);
            if (!(inputString >> externalInput)) {
                std::cout << "[   WARN   ] Improper input in text file. Skipping the test \n";
                continue;
            }
            inputString >> externalChecksum;
            externalInput.erase(std::remove(externalInput.begin(), externalInput.end(), ','),
                                 externalInput.end());
            externalChecksum.erase(
                    std::remove(externalChecksum.begin(), externalChecksum.end(), ','),
                    externalChecksum.end());

            std::string url = externalInput + ".bitstrm";
            std::string info = externalInput + ".info";
            char mimeType[50];
            int32_t err =
                extractBitstreamAndInfoFile(externalInput, (sResourceDir + url),
                                            (sResourceDir + info), mimeType);
            if (err) continue;

            lookUpTable.push_back({mimeType, url, info, externalChecksum});
        }
        infile.close();
    }
}
