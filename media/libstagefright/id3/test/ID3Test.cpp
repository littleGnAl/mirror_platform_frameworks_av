/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define LOG_TAG "ID3Test"
#include <utils/Log.h>

#include <ctype.h>
#include <string>
#include <map>
#include <sys/stat.h>
#include <datasource/FileSource.h>

#include <media/stagefright/foundation/hexdump.h>
#include <media/MediaExtractorPluginHelper.h>
#include <ID3.h>

#include "ID3TestEnvironment.h"

using namespace android;

static ID3TestEnvironment *gEnv = nullptr;

class ID3tagTest : public ::testing::TestWithParam<string> {};

class ID3versionTest : public ::testing::TestWithParam<pair<string, uint8_t>> {
  public:
    ID3versionTest() {
        mVersionMap.insert(pair<uint8_t, string>(ID3::ID3_UNKNOWN, "Unknown"));
        mVersionMap.insert(pair<uint8_t, string>(ID3::ID3_V1, "V1"));
        mVersionMap.insert(pair<uint8_t, string>(ID3::ID3_V1_1, "V1_1"));
        mVersionMap.insert(pair<uint8_t, string>(ID3::ID3_V2_2, "V2_2"));
        mVersionMap.insert(pair<uint8_t, string>(ID3::ID3_V2_3, "V2_3"));
        mVersionMap.insert(pair<uint8_t, string>(ID3::ID3_V2_4, "V2_4"));
    }

    map</*version*/ uint8_t, /*versionNameString*/ string> mVersionMap;
};

class ID3textTagTest : public ::testing::TestWithParam<pair<string, int>> {};
class ID3albumArtTest : public ::testing::TestWithParam<pair<string, bool>> {};
class ID3multiAlbumArtTest : public ::testing::TestWithParam<pair<string, int>> {};

TEST_P(ID3tagTest, TagTest) {
    string path = gEnv->getRes() + GetParam();
    sp<FileSource> file = new FileSource(path.c_str());
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";
    DataSourceHelper helper(file->wrap());
    ID3 tag(&helper);
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path.c_str() << "\n";

    ID3::Iterator it(tag, nullptr);
    while (!it.done()) {
        String8 id;
        it.getID(&id);
        ASSERT_GT(id.length(), 0) << "No ID tag found! \n";

        ALOGI("Found ID tag: %s\n", String8(id).c_str());
        it.next();
    }
}

TEST_P(ID3versionTest, VersionTest) {
    uint8_t version = GetParam().second;
    string path = gEnv->getRes() + GetParam().first;
    sp<android::FileSource> file = new FileSource(path.c_str());
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    DataSourceHelper helper(file->wrap());
    ID3 tag(&helper);
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path.c_str() << "\n";

    ASSERT_EQ(version, tag.version()) << "Expected version: " << mVersionMap[version]
                                      << " Found version: " << mVersionMap[tag.version()];
}

TEST_P(ID3textTagTest, TextTagTest) {
    int numTextFrames = GetParam().second;
    string path = gEnv->getRes() + GetParam().first;
    sp<android::FileSource> file = new FileSource(path.c_str());
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    DataSourceHelper helper(file->wrap());
    ID3 tag(&helper);
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path.c_str() << "\n";
    int countTextFrames = 0;
    ID3::Iterator it(tag, nullptr);
    if (tag.version() == ID3::ID3_V1 || tag.version() == ID3::ID3_V1_1) {
        while (!it.done()) {
            String8 id;
            String8 text;
            it.getID(&id);
            ASSERT_GT(id.length(), 0);

            it.getString(&text);
            // if the tag has a value
            if (strcmp(text.string(), "")) {
                countTextFrames++;
                ALOGI("ID: %s\n", id.c_str());
                ALOGI("Text string: %s\n", text.string());
            }
            it.next();
        }
    } else {
        while (!it.done()) {
            String8 id;
            it.getID(&id);
            ASSERT_GT(id.length(), 0);

            if (id[0] == 'T') {
                String8 text;
                countTextFrames++;
                it.getString(&text);
                ALOGI("Found text frame %s : %s \n", id.string(), text.string());
            }
            it.next();
        }
    }
    string newFile = GetParam().first;
    ASSERT_EQ(countTextFrames, numTextFrames)
            << "Expected " << numTextFrames << " text frames, found " << countTextFrames;
}

TEST_P(ID3albumArtTest, AlbumArtTest) {
    bool albumArtPresent = GetParam().second;
    string path = gEnv->getRes() + GetParam().first;
    sp<android::FileSource> file = new FileSource(path.c_str());
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    DataSourceHelper helper(file->wrap());
    ID3 tag(&helper);
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path.c_str() << "\n";
    size_t dataSize;
    String8 mime;
    const void *data = tag.getAlbumArt(&dataSize, &mime);

    if (albumArtPresent) {
        if (data) {
            ALOGV("Found album art: size = %zu mime = %s \n", dataSize, mime.string());
        }
        ASSERT_NE(data, nullptr) << "Expected album art, found none!" << path;
    } else {
        ASSERT_EQ(data, nullptr) << "Found album art when expected none!";
    }
#if (LOG_NDEBUG == 0)
    hexdump(data, dataSize > 128 ? 128 : dataSize);
#endif
}

TEST_P(ID3multiAlbumArtTest, MultiAlbumArtTest) {
    int numAlbumArt = GetParam().second;
    string path = gEnv->getRes() + GetParam().first;
    sp<android::FileSource> file = new FileSource(path.c_str());
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    DataSourceHelper helper(file->wrap());
    ID3 tag(&helper);
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path.c_str() << "\n";
    int count = 0;
    ID3::Iterator it(tag, nullptr);
    while (!it.done()) {
        String8 id;
        it.getID(&id);
        ASSERT_GT(id.length(), 0);
        // Check if the tag is an "APIC/PIC" tag.
        if (String8(id) == "APIC" || String8(id) == "PIC") {
            count++;
            size_t dataSize;
            String8 mime;
            const void *data = tag.getAlbumArt(&dataSize, &mime);
            if (data) {
                ALOGV("Found album art: size = %zu mime = %s \n", dataSize, mime.string());
#if (LOG_NDEBUG == 0)
                hexdump(data, dataSize > 128 ? 128 : dataSize);
#endif
            }
            ASSERT_NE(data, nullptr) << "Expected album art, found none!" << path;
        }
        it.next();
    }
    ASSERT_EQ(count, numAlbumArt) << "Found " << count << " album arts, expected " << numAlbumArt
                                  << " album arts! \n";
}

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3tagTest,
        ::testing::Values("bbb_44100hz_2ch_128kbps_1sec_v23.mp3",
                          "bbb_44100hz_2ch_128kbps_1sec_1_image.mp3",
                          "bbb_44100hz_2ch_128kbps_1sec_2_image.mp3",
                          "bbb_44100hz_2ch_128kbps_2sec_v24.mp3",
                          "bbb_44100hz_2ch_128kbps_2sec_1_image.mp3",
                          "bbb_44100hz_2ch_128kbps_2sec_2_image.mp3",
                          "bbb_44100hz_2ch_128kbps_2sec_largeSize.mp3",
                          "bbb_44100hz_2ch_128kbps_1sec_v23_3tags.mp3",
                          "bbb_44100hz_2ch_128kbps_1sec_v1_5tags.mp3",
                          "bbb_44100hz_2ch_128kbps_2sec_v24_unsynchronizedOneFrame.mp3",
                          "bbb_44100hz_2ch_128kbps_2sec_v24_unsynchronizedAllFrames.mp3"));

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3versionTest,
        ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_1sec_v23.mp3", ID3::ID3_V2_3),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_1_image.mp3", ID3::ID3_V2_3),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_2_image.mp3", ID3::ID3_V2_3),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_v24.mp3", ID3::ID3_V2_4),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_1_image.mp3", ID3::ID3_V2_4),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_2_image.mp3", ID3::ID3_V2_4),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_largeSize.mp3", ID3::ID3_V2_4),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_v23_3tags.mp3", ID3::ID3_V2_3),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_v1_5tags.mp3", ID3::ID3_V1_1),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_v1_3tags.mp3", ID3::ID3_V1_1),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_v24_unsynchronizedOneFrame.mp3",
                                    ID3::ID3_V2_4),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_v24_unsynchronizedAllFrames.mp3",
                                    ID3::ID3_V2_4)));

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3textTagTest,
        ::testing::Values(
                make_pair("bbb_44100hz_2ch_128kbps_1sec_v23.mp3", 1),
                make_pair("bbb_44100hz_2ch_128kbps_1sec_1_image.mp3", 1),
                make_pair("bbb_44100hz_2ch_128kbps_1sec_2_image.mp3", 1),
                make_pair("bbb_44100hz_2ch_128kbps_2sec_v24.mp3", 1),
                make_pair("bbb_44100hz_2ch_128kbps_2sec_1_image.mp3", 1),
                make_pair("bbb_44100hz_2ch_128kbps_2sec_2_image.mp3", 1),
                make_pair("bbb_44100hz_2ch_128kbps_2sec_largeSize.mp3", 1),
                make_pair("bbb_44100hz_2ch_128kbps_1sec_v23_3tags.mp3", 3),
                make_pair("bbb_44100hz_2ch_128kbps_1sec_v1_5tags.mp3", 5),
                make_pair("bbb_44100hz_2ch_128kbps_1sec_v1_3tags.mp3", 3),
                make_pair("bbb_44100hz_2ch_128kbps_2sec_v24_unsynchronizedOneFrame.mp3", 3),
                make_pair("bbb_44100hz_2ch_128kbps_2sec_v24_unsynchronizedAllFrames.mp3", 3)));

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3albumArtTest,
        ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_1sec_v23.mp3", false),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_1_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_2_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_v24.mp3", false),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_1_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_2_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_largeSize.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_v1_5tags.mp3", false)));

INSTANTIATE_TEST_SUITE_P(id3TestAll, ID3multiAlbumArtTest,
                         ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_1sec_v23.mp3", 0),
                                           make_pair("bbb_44100hz_2ch_128kbps_2sec_v24.mp3", 0),
                                           make_pair("bbb_44100hz_2ch_128kbps_1sec_1_image.mp3", 1),
                                           make_pair("bbb_44100hz_2ch_128kbps_2sec_1_image.mp3", 1),
                                           make_pair("bbb_44100hz_2ch_128kbps_1sec_2_image.mp3", 2),
                                           make_pair("bbb_44100hz_2ch_128kbps_2sec_2_image.mp3", 2),
                                           make_pair("bbb_44100hz_2ch_128kbps_2sec_largeSize.mp3",
                                                     3)));

int main(int argc, char **argv) {
    gEnv = new ID3TestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGI("ID3 Test result = %d\n", status);
    }
    return status;
}
