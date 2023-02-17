/*
**
** Copyright 2023, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

//#define LOG_NDEBUG 0
#define LOG_TAG "ResourceManagerMetrics"
#include <utils/Log.h>

#include <media/stagefright/ProcessInfo.h>
#include <stats_media_metrics.h>

#include "ProcessTerminationWatcher.h"
#include "ResourceManagerMetrics.h"

#include <cmath>

namespace android {

using stats::media_metrics::stats_write;
using stats::media_metrics::MEDIA_CODEC_STARTED;
using stats::media_metrics::MEDIA_CODEC_STOPPED;
using stats::media_metrics::MEDIA_CODEC_CONCURRENT_USAGE_REPORTED;
using stats::media_metrics::MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED;
using stats::media_metrics::MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_SUCCESS;
using stats::media_metrics::\
    MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_FAILED_NO_CLIENTS;
using stats::media_metrics::\
    MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_FAILED_RECLAIM_RESOURCES;

inline const char* getCodecType(MediaResourceSubType codecType) {
    switch (codecType) {
        case MediaResourceSubType::kAudioCodec:         return "Audio";
        case MediaResourceSubType::kVideoCodec:         return "Video";
        case MediaResourceSubType::kImageCodec:         return "Image";
        case MediaResourceSubType::kUnspecifiedSubType: return "Unspecified";
        default:                                        return "Unspecified";
    }
    return "Unspecified";
}

static CodecBucket getCodecBucket(bool isHardware,
                                  bool isEncoder,
                                  MediaResourceSubType codecType) {
    if (isHardware) {
        switch (codecType) {
            case MediaResourceSubType::kAudioCodec:
                if (isEncoder) return HwAudioEncoder;
                return HwAudioDecoder;
            case MediaResourceSubType::kVideoCodec:
                if (isEncoder) return HwVideoEncoder;
                return HwVideoDecoder;
            case MediaResourceSubType::kImageCodec:
                if (isEncoder) return HwImageEncoder;
                return HwImageDecoder;
            case MediaResourceSubType::kUnspecifiedSubType:
            default:
                return CodecBucketUnspecified;
        }
    } else {
        switch (codecType) {
            case MediaResourceSubType::kAudioCodec:
                if (isEncoder) return SwAudioEncoder;
                return SwAudioDecoder;
            case MediaResourceSubType::kVideoCodec:
                if (isEncoder) return SwVideoEncoder;
                return SwVideoDecoder;
            case MediaResourceSubType::kImageCodec:
                if (isEncoder) return SwImageEncoder;
                return SwImageDecoder;
            case MediaResourceSubType::kUnspecifiedSubType:
            default:
                return CodecBucketUnspecified;
        }
    }

    return CodecBucketUnspecified;
}

static bool getLogMessage(int hwCount, int swCount, std::string& logMsg) {
    bool update = false;
    if (hwCount > 0) {
        logMsg.append(" HW: " + std::to_string(hwCount));
        update = true;
    }
    if (swCount > 0) {
        logMsg.append(" SW: " + std::to_string(hwCount));
        update = true;
    }

    if (update) {
        logMsg.append(" ] ");
    }
    return update;
}

ResourceManagerMetrics::ResourceManagerMetrics(const sp<ProcessInfoInterface>& processInfo) {
    // Create a process termination watcher, with 5seconds of polling frequency.
    mProcessTerminationWatcher = std::make_unique<ProcessTerminationWatcher>(
        processInfo, [this] (const std::vector<int32_t>& pids) {
            onProcessTerminated(pids);
        }, 5s);
}

ResourceManagerMetrics::~ResourceManagerMetrics() {
}

void ResourceManagerMetrics::addPid(int pid) {
    std::scoped_lock lock(mLock);
    mProcessTerminationWatcher->addPid(pid);
}

void ResourceManagerMetrics::notifyClientCreated(const ClientInfoParcel& clientInfo) {
    std::scoped_lock lock(mLock);
    // Save the pid, uid information.
    mPidUidMap.emplace(clientInfo.pid, clientInfo.uid);
    // Update the resource instance count.
    std::map<std::string, int>::iterator found = mConcurrentResourceCountMap.find(clientInfo.name);
    if (found == mConcurrentResourceCountMap.end()) {
        mConcurrentResourceCountMap[clientInfo.name] = 1;
    } else {
        found->second++;
    }
}

void ResourceManagerMetrics::notifyClientReleased(const ClientInfoParcel& clientInfo) {
    bool stopCalled = true;
    ClientConfigMap::iterator found;
    {
        std::scoped_lock lock(mLock);
        found = mClientConfigMap.find(clientInfo.id);
        if (found != mClientConfigMap.end()) {
            // Release is called without Stop!
            stopCalled = false;
        }
    }
    if (!stopCalled) {
        // call Stop to update the metrics.
        notifyClientStopped(found->second);
    }
    {
        std::scoped_lock lock(mLock);
        // Update the resource instance count also.
        std::map<std::string, int>::iterator found =
            mConcurrentResourceCountMap.find(clientInfo.name);
        if (found != mConcurrentResourceCountMap.end()) {
            if (found->second > 0) {
                found->second--;
            }
        }
    }
}

void ResourceManagerMetrics::notifyClientStarted(const ClientConfigParcel& clientConfig) {
    std::scoped_lock lock(mLock);
    int pid = clientConfig.clientInfo.pid;
    // Update the active pid set.
    mProcessTerminationWatcher->addPid(pid);

    // Update the client config for thic client.
    mClientConfigMap[clientConfig.clientInfo.id] = clientConfig;

    // Update the concurrent codec count for this process.
    CodecBucket codecBucket = getCodecBucket(clientConfig.isHardware,
                                             clientConfig.isEncoder,
                                             clientConfig.codecType);
    increaseConcurrentCodecs(pid, codecBucket);

    if (clientConfig.codecType == MediaResourceSubType::kVideoCodec ||
        clientConfig.codecType == MediaResourceSubType::kImageCodec) {
        // Update the pixel count for this process
        increasePixelCount(pid, clientConfig.width * clientConfig.height);
    }

    // System concurrent codec usage
    int systemConcurrentCodecCount = mConcurrentCodecsMap[codecBucket];
    // Process/Application concurrent codec usage for this type of codec
    int appConcurrentCodecCount = mProcessConcurrentCodecsMap[pid].mCurrent[codecBucket];
    // Process/Application's current pixel count.
    long pixelCount = 0;
    std::map<int32_t, PixelCount>::iterator it = mProcessPixelsMap.find(pid);
    if (it != mProcessPixelsMap.end()) {
        pixelCount = it->second.mCurrent;
    }

    int result = stats_write(
         MEDIA_CODEC_STARTED,
         clientConfig.clientInfo.uid,
         clientConfig.id,
         clientConfig.clientInfo.name.c_str(),
         static_cast<int32_t>(clientConfig.codecType),
         clientConfig.isEncoder,
         clientConfig.isHardware,
         clientConfig.width, clientConfig.height,
         systemConcurrentCodecCount,
         appConcurrentCodecCount,
         pixelCount);

    ALOGV("%s: Pushed MEDIA_CODEC_STARTED atom: "
          "Requester[pid(%d): uid(%d)] "
          "Codec: [%s] is %s %s %s "
          "Timestamp: %jd "
          "Resolution: %d x %d "
          "ConcurrentCodec[%d]={System: %d App: %d} "
          "CodecId: [%jd] result: %d",
          __func__,
          pid, clientConfig.clientInfo.uid,
          clientConfig.clientInfo.name.c_str(),
          clientConfig.isHardware? "hardware" : "software",
          getCodecType(clientConfig.codecType),
          clientConfig.isEncoder? "encoder" : "decoder",
          clientConfig.timeStamp,
          clientConfig.width, clientConfig.height,
          codecBucket, systemConcurrentCodecCount, appConcurrentCodecCount,
          clientConfig.id, result);
}

void ResourceManagerMetrics::notifyClientStopped(const ClientConfigParcel& clientConfig) {
    std::scoped_lock lock(mLock);
    int pid = clientConfig.clientInfo.pid;
    // Update the concurrent codec count for this process.
    CodecBucket codecBucket = getCodecBucket(clientConfig.isHardware,
                                             clientConfig.isEncoder,
                                             clientConfig.codecType);
    decreaseConcurrentCodecs(pid, codecBucket);

    if (clientConfig.codecType == MediaResourceSubType::kVideoCodec ||
        clientConfig.codecType == MediaResourceSubType::kImageCodec) {
        // Update the pixel count for this process
        decreasePixelCount(pid, clientConfig.width * clientConfig.height);
    }

    // System concurrent codec usage
    int systemConcurrentCodecCount = mConcurrentCodecsMap[codecBucket];
    // Process/Application concurrent codec usage for this type of codec
    int appConcurrentCodecCount = 0;
    std::map<int32_t, ConcurrentCodecs>::iterator found = mProcessConcurrentCodecsMap.find(pid);
    if (found != mProcessConcurrentCodecsMap.end()) {
        appConcurrentCodecCount = found->second.mCurrent[codecBucket];
    }
    // Process/Application's current pixel count.
    long pixelCount = 0;
    std::map<int32_t, PixelCount>::iterator it = mProcessPixelsMap.find(pid);
    if (it != mProcessPixelsMap.end()) {
        pixelCount = it->second.mCurrent;
    }

    // calculate the usageTime as:
    //  MediaCodecStopped.clientConfig.timeStamp -
    //  MediaCodecStarted.clientConfig.timeStamp
    int64_t usageTime = 0;
    ClientConfigMap::iterator entry = mClientConfigMap.find(clientConfig.clientInfo.id);
    if (entry != mClientConfigMap.end()) {
        usageTime = clientConfig.timeStamp - entry->second.timeStamp;
        // And we can erase this config now.
        mClientConfigMap.erase(entry);
    } else {
        ALOGW("%s: Start Config is missing!", __func__);
    }

     int result = stats_write(
         MEDIA_CODEC_STOPPED,
         clientConfig.clientInfo.uid,
         clientConfig.id,
         clientConfig.clientInfo.name.c_str(),
         static_cast<int32_t>(clientConfig.codecType),
         clientConfig.isEncoder,
         clientConfig.isHardware,
         clientConfig.width, clientConfig.height,
         systemConcurrentCodecCount,
         appConcurrentCodecCount,
         pixelCount,
         usageTime);
    ALOGV("%s: Pushed MEDIA_CODEC_STOPPED atom: "
          "Requester[pid(%d): uid(%d)] "
          "Codec: [%s] is %s %s %s "
          "Timestamp: %jd Usage time: %jd "
          "Resolution: %d x %d "
          "ConcurrentCodec[%d]={System: %d App: %d} "
          "CodecID: [%jd] result: %d",
          __func__,
          pid, clientConfig.clientInfo.uid,
          clientConfig.clientInfo.name.c_str(),
          clientConfig.isHardware? "hardware" : "software",
          getCodecType(clientConfig.codecType),
          clientConfig.isEncoder? "encoder" : "decoder",
          clientConfig.timeStamp, usageTime,
          clientConfig.width, clientConfig.height,
          codecBucket, systemConcurrentCodecCount, appConcurrentCodecCount,
          clientConfig.id, result);
}

void ResourceManagerMetrics::onProcessTerminated(const std::vector<int32_t>& pids) {
    std::scoped_lock lock(mLock);
    for (int32_t pid : pids) {
        // For each terminated process, post MediaCodecConcurrentUsageReported
        pushConcurrentUsageReport(pid);
        mPidUidMap.erase(pid);
    }
}

void ResourceManagerMetrics::pushConcurrentUsageReport(int32_t pid) {
    // Process/Application peak concurrent codec usage
    PidUidMap::iterator entry = mPidUidMap.find(pid);
    int32_t uid = (entry == mPidUidMap.end()) ? 0 : entry->second;

    std::map<int32_t, ConcurrentCodecs>::iterator found = mProcessConcurrentCodecsMap.find(pid);
    if (found == mProcessConcurrentCodecsMap.end()) {
        ALOGI("%s: No MEDIA_CODEC_CONCURRENT_USAGE_REPORTED atom Entry for: "
              "Application[pid(%d): uid(%d)]", __func__, pid, uid);
        return;
    }
    const ConcurrentCodecsMap& codecsMap = found->second.mPeak;
    int peakHwAudioEncoderCount = codecsMap[HwAudioEncoder];
    int peakHwAudioDecoderCount = codecsMap[HwAudioDecoder];
    int peakHwVideoEncoderCount = codecsMap[HwVideoEncoder];
    int peakHwVideoDecoderCount = codecsMap[HwVideoDecoder];
    int peakHwImageEncoderCount = codecsMap[HwImageEncoder];
    int peakHwImageDecoderCount = codecsMap[HwImageDecoder];
    int peakSwAudioEncoderCount = codecsMap[SwAudioEncoder];
    int peakSwAudioDecoderCount = codecsMap[SwAudioDecoder];
    int peakSwVideoEncoderCount = codecsMap[SwVideoEncoder];
    int peakSwVideoDecoderCount = codecsMap[SwVideoDecoder];
    int peakSwImageEncoderCount = codecsMap[SwImageEncoder];
    int peakSwImageDecoderCount = codecsMap[SwImageDecoder];

    long peakPixels = 0;
    std::map<int32_t, PixelCount>::iterator it = mProcessPixelsMap.find(pid);
    if (it == mProcessPixelsMap.end()) {
        ALOGI("%s: No Video Codec Entry for Application[pid(%d): uid(%d)]",
              __func__, pid, uid);
    } else {
        peakPixels = it->second.mPeak;
    }
    std::string peakPixelsLog("Peak Pixels: " + std::to_string(peakPixels));

    std::string peakCodecLog("Peak { ");
    std::string logMsg("AudioEnc[");
    if (getLogMessage(peakHwAudioEncoderCount, peakSwAudioEncoderCount, logMsg)) {
        peakCodecLog.append(logMsg);
    }
    logMsg = "AudioDec[";
    if (getLogMessage(peakHwAudioDecoderCount, peakSwAudioDecoderCount, logMsg)) {
        peakCodecLog.append(logMsg);
    }
    logMsg = "VideoEnc[";
    if (getLogMessage(peakHwVideoEncoderCount, peakSwVideoEncoderCount, logMsg)) {
        peakCodecLog.append(logMsg);
    }
    logMsg = "VideoDec[";
    if (getLogMessage(peakHwVideoDecoderCount, peakSwVideoDecoderCount, logMsg)) {
        peakCodecLog.append(logMsg);
    }
    logMsg = "ImageEnc[";
    if (getLogMessage(peakHwImageEncoderCount, peakSwImageEncoderCount, logMsg)) {
        peakCodecLog.append(logMsg);
    }
    logMsg = "ImageDec[";
    if (getLogMessage(peakHwImageDecoderCount, peakSwImageDecoderCount, logMsg)) {
        peakCodecLog.append(logMsg);
    }
    peakCodecLog.append("}");

    int result = stats_write(
        MEDIA_CODEC_CONCURRENT_USAGE_REPORTED,
        uid,
        peakHwVideoDecoderCount,
        peakHwVideoEncoderCount,
        peakSwVideoDecoderCount,
        peakSwVideoEncoderCount,
        peakHwAudioDecoderCount,
        peakHwAudioEncoderCount,
        peakSwAudioDecoderCount,
        peakSwAudioEncoderCount,
        peakHwImageDecoderCount,
        peakHwImageEncoderCount,
        peakSwImageDecoderCount,
        peakSwImageEncoderCount,
        peakPixels);
    ALOGI("%s: Pushed MEDIA_CODEC_CONCURRENT_USAGE_REPORTED atom: "
          "Requester[pid(%d): uid(%d)] %s %s result: %d",
          __func__, pid, uid, peakCodecLog.c_str(), peakPixelsLog.c_str(), result);
}

void ResourceManagerMetrics::pushReclaimAtom(const ClientInfoParcel& clientInfo,
                        const std::vector<int>& priorities,
                        const Vector<std::shared_ptr<IResourceManagerClient>>& clients,
                        const PidUidVector& idList, bool reclaimed) {
    // Construct the metrics for codec reclaim as a pushed atom.
    // 1. Information about the requester.
    //  - UID and the priority (oom score)
    int32_t callingPid = clientInfo.pid;
    int32_t requesterUid = clientInfo.uid;
    std::string clientName = clientInfo.name;
    int requesterPriority = priorities[0];

    //  2. Information about the codec.
    //  - Name of the codec requested
    //  - Number of concurrent codecs running.
    int32_t noOfConcurrentCodecs = 0;
    std::map<std::string, int>::iterator found = mConcurrentResourceCountMap.find(clientName);
    if (found != mConcurrentResourceCountMap.end()) {
        noOfConcurrentCodecs = found->second;
    }

    // 3. Information about the Reclaim:
    // - Status of reclaim request
    // - How many codecs are reclaimed
    // - For each codecs reclaimed, information of the process that it belonged to:
    //    - UID and the Priority (oom score)
    int32_t reclaimStatus = MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_SUCCESS;
    if (!reclaimed) {
      if (clients.size() == 0) {
        // No clients to reclaim from
        reclaimStatus =
            MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_FAILED_NO_CLIENTS;
      } else {
        // Couldn't reclaim resources from the clients
        reclaimStatus =
            MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED__RECLAIM_STATUS__RECLAIM_FAILED_RECLAIM_RESOURCES;
      }
    }
    int32_t noOfCodecsReclaimed = clients.size();
    int32_t targetIndex = 1;
    for (PidUidVector::const_reference id : idList) {
        int32_t targetUid = id.second;
        int targetPriority = priorities[targetIndex];
        // Post the pushed atom
        int result = stats_write(
            MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED,
            requesterUid,
            requesterPriority,
            clientName.c_str(),
            noOfConcurrentCodecs,
            reclaimStatus,
            noOfCodecsReclaimed,
            targetIndex,
            targetUid,
            targetPriority);
        ALOGI("%s: Pushed MEDIA_CODEC_RECLAIM_REQUEST_COMPLETED atom: "
              "Requester[pid(%d): uid(%d): priority(%d)] "
              "Codec: [%s] "
              "No of concurrent codecs: %d "
              "Reclaim Status: %d "
              "No of codecs reclaimed: %d "
              "Target[%d][pid(%d): uid(%d): priority(%d)] result: %d",
              __func__, callingPid, requesterUid, requesterPriority,
              clientName.c_str(), noOfConcurrentCodecs,
              reclaimStatus, noOfCodecsReclaimed,
              targetIndex, id.first, targetUid, targetPriority, result);
        targetIndex++;
    }
}

void ResourceManagerMetrics::increaseConcurrentCodecs(int32_t pid,
                                                      CodecBucket codecBucket) {
    // Increase the codec usage across the system.
    mConcurrentCodecsMap[codecBucket]++;

    // Now update the codec usage for this (pid) process.
    std::map<int32_t, ConcurrentCodecs>::iterator found = mProcessConcurrentCodecsMap.find(pid);
    if (found == mProcessConcurrentCodecsMap.end()) {
        ConcurrentCodecs codecs;
        codecs.mCurrent[codecBucket] = 1;
        codecs.mPeak[codecBucket] = 1;
        mProcessConcurrentCodecsMap.emplace(pid, codecs);
    } else {
        found->second.mCurrent[codecBucket]++;
        // Check if it's the peak count for this slot.
        if (found->second.mPeak[codecBucket] < found->second.mCurrent[codecBucket]) {
            found->second.mPeak[codecBucket] = found->second.mCurrent[codecBucket];
        }
    }
}

void ResourceManagerMetrics::decreaseConcurrentCodecs(int32_t pid,
                                                      CodecBucket codecBucket) {
    // Decrease the codec usage across the system.
    if (mConcurrentCodecsMap[codecBucket] > 0) {
        mConcurrentCodecsMap[codecBucket]--;
    }

    // Now update the codec usage for this (pid) process.
    std::map<int32_t, ConcurrentCodecs>::iterator found = mProcessConcurrentCodecsMap.find(pid);
    if (found != mProcessConcurrentCodecsMap.end()) {
        if (found->second.mCurrent[codecBucket] > 0) {
            found->second.mCurrent[codecBucket]--;
        }
    }
}

void ResourceManagerMetrics::increasePixelCount(int32_t pid, long pixels) {
    // Now update the current pixel usage for this (pid) process.
    std::map<int32_t, PixelCount>::iterator found = mProcessPixelsMap.find(pid);
    if (found == mProcessPixelsMap.end()) {
        PixelCount pixelCount {pixels, pixels};
        mProcessPixelsMap.emplace(pid, pixelCount);
    } else {
        found->second.mCurrent += pixels;
        // Check if it's the peak count for this slot.
        if (found->second.mPeak < found->second.mCurrent) {
            found->second.mPeak = found->second.mCurrent;
        }
    }
}

void ResourceManagerMetrics::decreasePixelCount(int32_t pid, long pixels) {
    // Now update the current pixel usage for this (pid) process.
    std::map<int32_t, PixelCount>::iterator found = mProcessPixelsMap.find(pid);
    if (found != mProcessPixelsMap.end()) {
        if (found->second.mCurrent < pixels) {
            found->second.mCurrent = 0;
        } else {
            found->second.mCurrent -= pixels;
        }
    }
}

long ResourceManagerMetrics::getPeakConcurrentPixelCount(int pid) const {
    std::map<int32_t, PixelCount>::const_iterator found = mProcessPixelsMap.find(pid);
    if (found != mProcessPixelsMap.end()) {
        return found->second.mPeak;
    }

    return 0;
}

long ResourceManagerMetrics::getConcurrentPixelCount(int pid) const {
    std::map<int32_t, PixelCount>::const_iterator found = mProcessPixelsMap.find(pid);
    if (found != mProcessPixelsMap.end()) {
        return found->second.mCurrent;
    }

    return 0;
}

} // namespace android
