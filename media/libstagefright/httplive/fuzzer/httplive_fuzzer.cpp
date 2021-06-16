/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "fuzzer/FuzzedDataProvider.h"
#include <fstream>
#include <httplive/LiveDataSource.h>
#include <httplive/LiveSession.h>
#include <media/MediaHTTPConnection.h>
#include <media/MediaHTTPService.h>
#include <media/mediaplayer_common.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/ALooper.h>
#include <string>
#include <utils/Log.h>

using namespace std;
using namespace android;

constexpr char kFileName[] = "httplive.m3u8";
constexpr char kFileUrlPrefix[] = "file://";
constexpr int64_t kOffSet = 0;
constexpr int32_t kReadyMarkMs = 5000;
constexpr int32_t kPrepareMarkMs = 1500;
constexpr int32_t kErrorNoMax = -1;
constexpr int32_t kErrorNoMin = -34;
constexpr int32_t kMaxTimeUs = 10000000;
constexpr int32_t kRandomStringLength = 64;
constexpr int32_t kRangeMin = 0;
constexpr int32_t kRangeMax = 1000;

constexpr LiveSession::StreamType kValidStreamType[] = {
    LiveSession::STREAMTYPE_AUDIO, LiveSession::STREAMTYPE_VIDEO,
    LiveSession::STREAMTYPE_SUBTITLES, LiveSession::STREAMTYPE_METADATA};

constexpr MediaSource::ReadOptions::SeekMode kValidSeekMode[] = {
    MediaSource::ReadOptions::SeekMode::SEEK_PREVIOUS_SYNC,
    MediaSource::ReadOptions::SeekMode::SEEK_NEXT_SYNC,
    MediaSource::ReadOptions::SeekMode::SEEK_CLOSEST_SYNC,
    MediaSource::ReadOptions::SeekMode::SEEK_CLOSEST,
    MediaSource::ReadOptions::SeekMode::SEEK_FRAME_INDEX};

constexpr media_track_type kValidMediaTrackType[] = {
    MEDIA_TRACK_TYPE_UNKNOWN,  MEDIA_TRACK_TYPE_VIDEO,
    MEDIA_TRACK_TYPE_AUDIO,    MEDIA_TRACK_TYPE_TIMEDTEXT,
    MEDIA_TRACK_TYPE_SUBTITLE, MEDIA_TRACK_TYPE_METADATA};

struct TestAHandler : public AHandler {
  TestAHandler() {}
  virtual ~TestAHandler() {}

protected:
  void onMessageReceived(const sp<AMessage> & /*msg*/) override { return; }
};

struct TestMediaHTTPConnection : public MediaHTTPConnection {
  TestMediaHTTPConnection() {}
  virtual ~TestMediaHTTPConnection() {}

  virtual bool connect(const char * /*uri*/,
                       const KeyedVector<String8, String8> * /*headers*/) {
    return true;
  }

  virtual void disconnect() { return; }
  virtual ssize_t readAt(off64_t /*offset*/, void * /*data*/, size_t /*size*/) {
    return 0;
  }
  virtual off64_t getSize() { return 0; }
  virtual status_t getMIMEType(String8 * /*mimeType*/) { return NO_ERROR; }
  virtual status_t getUri(String8 * /*uri*/) { return NO_ERROR; }

private:
  DISALLOW_EVIL_CONSTRUCTORS(TestMediaHTTPConnection);
};

struct TestMediaHTTPService : public MediaHTTPService {
public:
  TestMediaHTTPService() {}
  ~TestMediaHTTPService(){};

  virtual sp<MediaHTTPConnection> makeHTTPConnection() {
    mediaHTTPConnection = sp<TestMediaHTTPConnection>::make();
    return mediaHTTPConnection;
  }

private:
  sp<TestMediaHTTPConnection> mediaHTTPConnection = nullptr;
  DISALLOW_EVIL_CONSTRUCTORS(TestMediaHTTPService);
};

class HttpLiveFuzzer {
public:
  void process(const uint8_t *data, size_t size);
  void deInitLiveSession();
  ~HttpLiveFuzzer() { deInitLiveSession(); }

private:
  void invokeLiveDataSource();
  void createM3U8File(const uint8_t *data, size_t size);
  void initLiveDataSource();
  void invokeLiveSession();
  void initLiveSession();
  void invokeDequeueAccessUnit();
  void invokeConnectAsync();
  void invokeSeekTo();
  void invokeGetConfig();
  sp<LiveDataSource> mLiveDataSource = nullptr;
  sp<LiveSession> mLiveSession = nullptr;
  sp<ALooper> mLiveLooper = nullptr;
  sp<TestMediaHTTPService> httpService = nullptr;
  sp<TestAHandler> handler = nullptr;
  FuzzedDataProvider *mFDP = nullptr;
};

void HttpLiveFuzzer::createM3U8File(const uint8_t *data, size_t size) {
  ofstream m3u8File;
  m3u8File.open(kFileName, ios::out | ios::binary);
  m3u8File.write((char *)data, size);
  m3u8File.close();
}

void HttpLiveFuzzer::initLiveDataSource() {
  mLiveDataSource = sp<LiveDataSource>::make();
}

void HttpLiveFuzzer::invokeLiveDataSource() {
  initLiveDataSource();
  size_t size = mFDP->ConsumeIntegralInRange<size_t>(kRangeMin, kRangeMax);
  sp<ABuffer> buffer = new ABuffer(size);
  mLiveDataSource->queueBuffer(buffer);
  uint8_t *data = new uint8_t[size];
  mLiveDataSource->readAtNonBlocking(kOffSet, data, size);
  int32_t finalResult = mFDP->ConsumeIntegralInRange(kErrorNoMin, kErrorNoMax);
  mLiveDataSource->queueEOS(finalResult);
  mLiveDataSource->reset();
  mLiveDataSource->countQueuedBuffers();
  delete[] data;
}

void HttpLiveFuzzer::initLiveSession() {
  handler = sp<TestAHandler>::make();
  mLiveLooper = sp<ALooper>::make();
  mLiveLooper->setName("http live");
  mLiveLooper->start();
  mLiveLooper->registerHandler(handler);
  uint32_t what = mFDP->ConsumeIntegral<uint32_t>();
  sp<AMessage> notify = sp<AMessage>::make(what, handler);
  httpService = new TestMediaHTTPService();
  uint32_t flags = mFDP->ConsumeIntegral<uint32_t>();
  mLiveSession = sp<LiveSession>::make(notify, flags, httpService);
  mLiveLooper->registerHandler(mLiveSession);
}

void HttpLiveFuzzer::invokeDequeueAccessUnit() {
  LiveSession::StreamType stream = mFDP->PickValueInArray(kValidStreamType);
  sp<ABuffer> buffer;
  mLiveSession->dequeueAccessUnit(stream, &buffer);
}

void HttpLiveFuzzer::invokeSeekTo() {
  int64_t timeUs = mFDP->ConsumeIntegralInRange<int64_t>(0, kMaxTimeUs);
  MediaSource::ReadOptions::SeekMode mode =
      mFDP->PickValueInArray(kValidSeekMode);
  mLiveSession->seekTo(timeUs, mode);
}

void HttpLiveFuzzer::invokeGetConfig() {
  mLiveSession->getTrackCount();
  size_t trackIndex = mFDP->ConsumeIntegral<size_t>();
  mLiveSession->getTrackInfo(trackIndex);
  media_track_type type = mFDP->PickValueInArray(kValidMediaTrackType);
  mLiveSession->getSelectedTrack(type);
  sp<MetaData> meta;
  LiveSession::StreamType stream = mFDP->PickValueInArray(kValidStreamType);
  mLiveSession->getStreamFormatMeta(stream, &meta);
  mLiveSession->getKeyForStream(stream);
  if (stream != LiveSession::STREAMTYPE_SUBTITLES) {
    mLiveSession->getSourceTypeForStream(stream);
  }
}

void HttpLiveFuzzer::invokeConnectAsync() {
  size_t fileUrlLength = strlen(kFileName) + strlen(kFileUrlPrefix);
  char *url = new char[fileUrlLength + 1];
  strcpy(url, kFileUrlPrefix);
  strcat(url, kFileName);
  string str_1 = mFDP->ConsumeRandomLengthString(kRandomStringLength);
  string str_2 = mFDP->ConsumeRandomLengthString(kRandomStringLength);

  KeyedVector<String8, String8> headers;
  headers.add(String8(str_1.c_str()), String8(str_2.c_str()));
  mLiveSession->connectAsync(url, &headers);
}

void HttpLiveFuzzer::invokeLiveSession() {
  initLiveSession();
  BufferingSettings bufferingSettings;
  bufferingSettings.mInitialMarkMs = kPrepareMarkMs;
  bufferingSettings.mResumePlaybackMarkMs = kReadyMarkMs;
  mLiveSession->setBufferingSettings(bufferingSettings);
  invokeConnectAsync();
  if (mLiveSession->isSeekable()) {
    invokeSeekTo();
  }
  invokeDequeueAccessUnit();
  size_t index = mFDP->ConsumeIntegral<size_t>();
  bool select = mFDP->ConsumeBool();
  mLiveSession->selectTrack(index, select);
  mLiveSession->hasDynamicDuration();
  int64_t firstTimeUs =
      mFDP->ConsumeIntegralInRange<int64_t>(kRangeMin, kRangeMax);
  int64_t timeUs = mFDP->ConsumeIntegralInRange<int64_t>(kRangeMin, kRangeMax);
  int32_t discontinuitySeq = mFDP->ConsumeIntegral<int32_t>();
  mLiveSession->calculateMediaTimeUs(firstTimeUs, timeUs, discontinuitySeq);
  invokeGetConfig();
}

void HttpLiveFuzzer::process(const uint8_t *data, size_t size) {
  mFDP = new FuzzedDataProvider(data, size);
  createM3U8File(data, size);
  invokeLiveDataSource();
  invokeLiveSession();
  delete mFDP;
}

void HttpLiveFuzzer::deInitLiveSession() {
  if (mLiveSession != NULL) {
    mLiveSession->disconnect();
    mLiveLooper->unregisterHandler(mLiveSession->id());
    mLiveLooper->unregisterHandler(handler->id());
    mLiveLooper->stop();
  }
  mLiveSession.clear();
  mLiveLooper.clear();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  HttpLiveFuzzer httpliveFuzzer;
  httpliveFuzzer.process(data, size);
  return 0;
}
