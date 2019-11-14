/*
 * Copyright (C) 2009 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "ExtractorUnitTest"
#include <utils/Log.h>

#include <datasource/FileSource.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaDataUtils.h>

#include "aac/AACExtractor.h"
#include "amr/AMRExtractor.h"
#include "flac/FLACExtractor.h"
#include "midi/MidiExtractor.h"
#include "mkv/MatroskaExtractor.h"
#include "mp3/MP3Extractor.h"
#include "mp4/MPEG4Extractor.h"
#include "mp4/SampleTable.h"
#include "mpeg2/MPEG2PSExtractor.h"
#include "mpeg2/MPEG2TSExtractor.h"
#include "ogg/OggExtractor.h"
#include "wav/WAVExtractor.h"

#include "ExtractorUnitTestEnvironment.h"

using namespace android;

constexpr int32_t kMaxCount = 10;

static ExtractorTestEnvironment *gEnv = nullptr;

class ExtractorUnitTest : public ::testing::TestWithParam<pair<string, string>> {
  public:
    virtual void SetUp() override {
        mDataSource = nullptr;
        mExtractor = nullptr;
        mExtractorName = unknown_comp;
        mDisableTest = false;

        std::map<std::string, standardExtractors> mapExtractor = {
                {"aac", AAC},     {"amr", AMR},         {"mp3", MP3},        {"ogg", OGG},
                {"wav", WAV},     {"mkv", MKV},         {"flac", FLAC},      {"midi", MIDI},
                {"mpeg4", MPEG4}, {"mpeg2ts", MPEG2TS}, {"mpeg2ps", MPEG2PS}};
        // Find the component type
        string writerFormat = GetParam().first;
        if (mapExtractor.find(writerFormat) != mapExtractor.end()) {
            mExtractorName = mapExtractor[writerFormat];
        }
        if (mExtractorName == standardExtractors::unknown_comp) {
            cout << "[   WARN   ] Test Skipped. Invalid extractor\n";
            mDisableTest = true;
        }
    }

    virtual void TearDown() override {
        if (mInputFp) fclose(mInputFp);
        if (mDataSource) mDataSource.clear();
        if (mExtractor) delete mExtractor;
    }

    int32_t setDataSource(string inputFileName);

    int32_t createExtractor();

    enum standardExtractors {
        AAC,
        AMR,
        FLAC,
        MIDI,
        MKV,
        MP3,
        MPEG4,
        MPEG2PS,
        MPEG2TS,
        OGG,
        WAV,
        unknown_comp,
    };

    bool mDisableTest;
    standardExtractors mExtractorName;

    FILE *mInputFp;
    sp<DataSource> mDataSource;
    MediaExtractorPluginHelper *mExtractor;
};

int32_t ExtractorUnitTest::setDataSource(string inputFileName) {
    mInputFp = fopen(inputFileName.c_str(), "rb");
    if (!mInputFp) {
        ALOGE("Unable to open input file for reading");
        return -1;
    }
    struct stat buf;
    stat(inputFileName.c_str(), &buf);
    int32_t fd = fileno(mInputFp);
    mDataSource = new FileSource(dup(fd), 0, buf.st_size);
    if (!mDataSource) return -1;
    return 0;
}

int32_t ExtractorUnitTest::createExtractor() {
    switch (mExtractorName) {
        case AAC:
            mExtractor = new AACExtractor(new DataSourceHelper(mDataSource->wrap()), 0);
            break;
        case AMR:
            mExtractor = new AMRExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MP3:
            mExtractor = new MP3Extractor(new DataSourceHelper(mDataSource->wrap()), nullptr);
            break;
        case OGG:
            mExtractor = new OggExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case WAV:
            mExtractor = new WAVExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MKV:
            mExtractor = new MatroskaExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case FLAC:
            mExtractor = new FLACExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MPEG4:
            mExtractor = new MPEG4Extractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MPEG2TS:
            mExtractor = new MPEG2TSExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MPEG2PS:
            mExtractor = new MPEG2PSExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        default:
            return -1;
    }
    if (!mExtractor) return -1;
    return 0;
}

TEST_P(ExtractorUnitTest, CreateExtractorTest) {
    if (mDisableTest) return;

    ALOGV("Checks if a valid extractor is created for a given input file");
    string inputFileName = gEnv->getRes() + GetParam().second;

    int32_t status = setDataSource(inputFileName);
    EXPECT_EQ(status, 0) << "SetDataSource failed for" << GetParam().first << "extractor";

    status = createExtractor();
    EXPECT_EQ(status, 0) << "Extractor creation failed for" << GetParam().first << "extractor";

    // A valid extractor instace should return success for following calls
    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0);

    AMediaFormat *format = AMediaFormat_new();
    status = mExtractor->getMetaData(format);
    ASSERT_EQ(status, AMEDIA_OK);
    AMediaFormat_delete(format);
}

TEST_P(ExtractorUnitTest, ExtractorTest) {
    if (mDisableTest) return;

    ALOGV("Validates %s Extractor for a given input file", GetParam().first.c_str());
    string inputFileName = gEnv->getRes() + GetParam().second;

    int32_t status = setDataSource(inputFileName);
    EXPECT_EQ(status, 0) << "SetDataSource failed for" << GetParam().first << "extractor";

    status = createExtractor();
    EXPECT_EQ(status, 0) << "Extractor creation failed for" << GetParam().first << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0);
    MediaTrackHelper *track;
    for (int32_t idx = 0; idx < numTracks; idx++) {
        track = mExtractor->getTrack(idx);
        if (!track) {
            ALOGE("Failed to get track for %s", inputFileName.c_str());
            ASSERT_TRUE(false);
        }
        CMediaTrack *cTrack = wrap(track);
        if (!cTrack) {
            ALOGE("Failed to get track for %s", inputFileName.c_str());
            ASSERT_TRUE(false);
        }
        MediaBufferGroup *bufferGroup = new MediaBufferGroup();
        status = cTrack->start(track, bufferGroup->wrap());
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to start the track";

        FILE *outFp = fopen(("extractorOutput" + to_string(idx)).c_str(), "wb");
        if (!outFp) {
            ALOGW("Unable to open output file for dumping extracted stream");
        }

        while (status != AMEDIA_ERROR_END_OF_STREAM) {
            MediaBufferHelper *buffer = nullptr;
            status = track->read(&buffer);
            ALOGV("track->read Status = %d buffer %p", status, buffer);
            if (buffer) {
                ALOGV("buffer->data %p buffer->size() %zu buffer->range_length() %zu",
                      buffer->data(), buffer->size(), buffer->range_length());
                if (outFp) fwrite(buffer->data(), 1, buffer->range_length(), outFp);
                buffer->release();
            }
        }
        if (outFp) fclose(outFp);
        ASSERT_EQ(OK, cTrack->stop(track)) << "Failed to stop the track";
        delete bufferGroup;
    }
    delete track;
}

TEST_P(ExtractorUnitTest, MetaDataComparisonTest) {
    if (mDisableTest) return;

    ALOGV("Validates Extractor's meta data for a given input file");
    string inputFileName = gEnv->getRes() + GetParam().second;

    int32_t status = setDataSource(inputFileName);
    EXPECT_EQ(status, 0) << "SetDataSource failed for" << GetParam().first << "extractor";

    status = createExtractor();
    EXPECT_EQ(status, 0) << "Extractor creation failed for" << GetParam().first << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0);
    MediaTrackHelper *track;
    AMediaFormat *extractorFormat = AMediaFormat_new();
    AMediaFormat *trackFormat = AMediaFormat_new();
    if (!extractorFormat || !trackFormat) {
        cout << "[   WARN   ] Test Skipped. AMediaFormat_new failed. This test cannot run without "
                "a valid AMediaFormat \n";
        return;
    }
    for (int32_t idx = 0; idx < numTracks; idx++) {
        track = mExtractor->getTrack(idx);
        if (!track) {
            ALOGE("Failed to get track for %s", inputFileName.c_str());
            ASSERT_TRUE(false);
        }
        CMediaTrack *cTrack = wrap(track);
        if (!cTrack) {
            ALOGE("Failed to get track for %s", inputFileName.c_str());
            ASSERT_TRUE(false);
        }
        MediaBufferGroup *bufferGroup = new MediaBufferGroup();
        status = cTrack->start(track, bufferGroup->wrap());
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to start the track";

        status = mExtractor->getTrackMetaData(extractorFormat, idx, 1);
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to get trackMetaData";

        status = track->getFormat(trackFormat);
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to get track meta data";

        const char *extractorMime, *trackMime;
        AMediaFormat_getString(extractorFormat, AMEDIAFORMAT_KEY_MIME, &extractorMime);
        AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &trackMime);
        if (!strcmp(extractorMime, trackMime)) {
            if (!strncmp(extractorMime, "audio/", 6)) {
                int32_t exSampleRate, exChannelCount;
                int32_t trackSampleRate, trackChannelCount;
                AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                      &exChannelCount);
                AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_SAMPLE_RATE, &exSampleRate);
                AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                      &trackChannelCount);
                AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_SAMPLE_RATE, &trackSampleRate);
                ASSERT_EQ(exChannelCount, trackChannelCount) << "ChannelCount not as expected";
                ASSERT_EQ(exSampleRate, trackSampleRate) << "SampleRate not as expected";
            } else {
                int32_t exWidth, exHeight;
                int32_t trackWidth, trackHeight;
                AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_WIDTH, &exWidth);
                AMediaFormat_getInt32(extractorFormat, AMEDIAFORMAT_KEY_HEIGHT, &exHeight);
                AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_WIDTH, &trackWidth);
                AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_HEIGHT, &trackHeight);
                ASSERT_EQ(exWidth, trackWidth) << "Width not as expected";
                ASSERT_EQ(exHeight, trackHeight) << "Height not as expected";
            }
        } else {
            ALOGE("Extractor's format doesn't match track format");
            ALOGE("Extractor Format %s", AMediaFormat_toString(extractorFormat));
            ALOGE("Track Format %s", AMediaFormat_toString(trackFormat));
            ASSERT_TRUE(false);
        }
        ASSERT_EQ(OK, cTrack->stop(track)) << "Failed to stop the track";
        delete bufferGroup;
    }
    delete track;
    AMediaFormat_delete(trackFormat);
    AMediaFormat_delete(extractorFormat);
}

TEST_P(ExtractorUnitTest, MultipleStartStopTest) {
    if (mDisableTest) return;

    ALOGV("Test %s extractor for multiple start and stop calls", GetParam().first.c_str());
    string inputFileName = gEnv->getRes() + GetParam().second;
    mInputFp = fopen(inputFileName.c_str(), "rb");
    if (!mInputFp) {
        cout << "[   WARN   ] Test Skipped. Unable to open input file for reading \n";
        return;
    }
    int32_t status = setDataSource(inputFileName);
    EXPECT_EQ(status, 0) << "SetDataSource failed for" << GetParam().first << "extractor";

    status = createExtractor();
    EXPECT_EQ(status, 0) << "Extractor creation failed for" << GetParam().first << "extractor";

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0);
    MediaTrackHelper *track;
    // start/stop the tracks multiple times
    for (int32_t count = 0; count < kMaxCount; count++) {
        for (int32_t idx = 0; idx < numTracks; idx++) {
            track = mExtractor->getTrack(idx);
            if (!track) {
                ALOGE("Failed to get track for %s", inputFileName.c_str());
                ASSERT_TRUE(false);
            }
            CMediaTrack *cTrack = wrap(track);
            if (!cTrack) {
                ALOGE("Failed to get track for %s", inputFileName.c_str());
                ASSERT_TRUE(false);
            }
            MediaBufferGroup *bufferGroup = new MediaBufferGroup();
            status = cTrack->start(track, bufferGroup->wrap());
            ASSERT_EQ(OK, (media_status_t)status) << "Failed to start the track";
            MediaBufferHelper *buffer = nullptr;
            status = track->read(&buffer);
            if (buffer) {
                ALOGV("buffer->data %p buffer->size() %zu buffer->range_length() %zu",
                      buffer->data(), buffer->size(), buffer->range_length());
                buffer->release();
            }
            ASSERT_EQ(OK, cTrack->stop(track)) << "Failed to stop the track";
            delete bufferGroup;
        }
    }
    delete track;
}

// TODO: (b/145332185)
// Add MIDI inputs
INSTANTIATE_TEST_SUITE_P(ExtractorUnitTestAll, ExtractorUnitTest,
                         ::testing::Values(make_pair("aac", "loudsoftaac.aac"),
                                           make_pair("amr", "testamr.amr"),
                                           make_pair("amr", "amrwb.wav"),
                                           make_pair("ogg", "john_cage.ogg"),
                                           make_pair("wav", "monotestgsm.wav"),
                                           make_pair("mpeg2ts", "segment000001.ts"),
                                           make_pair("flac", "sinesweepflac.flac"),
                                           make_pair("ogg", "testopus.opus"),
                                           make_pair("mkv", "sinesweepvorbis.mkv"),
                                           make_pair("mpeg4", "sinesweepoggmp4.mp4"),
                                           make_pair("mp3", "sinesweepmp3lame.mp3"),
                                           make_pair("mkv", "swirl_144x136_vp9.webm"),
                                           make_pair("mkv", "swirl_144x136_vp8.webm"),
                                           make_pair("mpeg2ps", "swirl_144x136_mpeg2.mpg"),
                                           make_pair("mpeg4", "swirl_132x130_mpeg4.mp4")));

int main(int argc, char **argv) {
    gEnv = new ExtractorTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}