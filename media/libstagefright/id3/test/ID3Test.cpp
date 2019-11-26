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
#include <sys/stat.h>
#include <datasource/FileSource.h>

#include <media/stagefright/foundation/hexdump.h>
#include <ID3.h>

#include "ID3TestEnvironment.h"

using namespace android;

static ID3TestEnvironment *gEnv = nullptr;

class ID3tagTest : public ::testing::TestWithParam<string> {};
class ID3versionTest : public ::testing::TestWithParam<pair<string, int>> {};
class ID3textTagTest : public ::testing::TestWithParam<pair<string, bool>> {};
class ID3albumArtTest : public ::testing::TestWithParam<pair<string, bool>> {};
class ID3multiAlbumArtTest : public ::testing::TestWithParam<pair<string, int>> {};

TEST_P(ID3tagTest, TagTest) {
    const char *path = (gEnv->getRes() + GetParam()).c_str();
    sp<FileSource> file = new FileSource(path);
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";
    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path << "\n";

    ID3::Iterator it(tag, nullptr);
    while (!it.done()) {
        String8 id;
        it.getID(&id);
        ASSERT_GT(id.length(), 0) << "No ID tag found! \n";
        ALOGV("Found ID tag: %s\n", String8(id).c_str());
        it.next();
    }
}

TEST_P(ID3versionTest, VersionTest) {
    int versionNumber = GetParam().second;
    const char *path = (gEnv->getRes() + GetParam().first).c_str();
    sp<android::FileSource> file = new FileSource(path);
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path << "\n";
    ASSERT_TRUE(tag.version() >= versionNumber) << "Found lower version tag! \n";
    ALOGV("Version: %d", tag.version());
}

TEST_P(ID3textTagTest, TextTagTest) {
    bool textFrame = GetParam().second;
    const char *path = (gEnv->getRes() + GetParam().first).c_str();
    sp<android::FileSource> file = new FileSource(path);
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path << "\n";
    int textFrameFlag = 0;
    ID3::Iterator it(tag, nullptr);
    while (!it.done()) {
        String8 id;
        it.getID(&id);

        ASSERT_GT(id.length(), 0);
        if (!textFrame) {
            ASSERT_EQ(id[0], 'T') << "Expected no text frame, found one!\n";
        } else if (textFrame && id[0] == 'T') {
            String8 text;
            textFrameFlag = 1;
            it.getString(&text);
            ALOGV("Found text frame %s : %s \n", id.string(), text.string());
        }
        it.next();
    }
    if(textFrame) {
        ASSERT_EQ(textFrameFlag, 1);
    }
}

TEST_P(ID3albumArtTest, AlbumArtTest) {
    bool sizeRestriction = GetParam().second;
    const char *path = (gEnv->getRes() + GetParam().first).c_str();
    sp<android::FileSource> file = new FileSource(path);
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path << "\n";
    size_t dataSize;
    String8 mime;
    const void *data = tag.getAlbumArt(&dataSize, &mime);

    // No sizeRestriction means the size can also be zero i.e. no album art.
    if (!sizeRestriction) {
        return;
    }
    ASSERT_TRUE(data) << "No album art found for file " << path;
    // kMaxMetadataSize = 3 * 1024 * 1024 i.e. 3MB limit set by the ID3 library
    static const size_t kMaxMetadataSize = 3 * 1024 * 1024;
    ASSERT_TRUE(dataSize < kMaxMetadataSize)
            << "Album art size more than specifications i.e. 3MB! \n";
    ALOGV("Found album art: size = %zu mime = %s \n", dataSize, mime.string());

#ifdef LOG_NDEBUG
    hexdump(data, dataSize > 128 ? 128 : dataSize);
#endif
}

TEST_P(ID3multiAlbumArtTest, MultiAlbumArtTest) {
    int numAlbumArt = GetParam().second;
    const char *path = (gEnv->getRes() + GetParam().first).c_str();
    sp<android::FileSource> file = new FileSource(path);
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path << "\n";
    int count = 0;
    ID3::Iterator it(tag, nullptr);
    while (!it.done()) {
        String8 id;
        it.getID(&id);
        ASSERT_GT(id.length(), 0);
        // Check if the tag is an "APIC/PIC" tag.
        if (String8(id) == "APIC" || String8(id) == "PIC") count++;
        it.next();
    }
    ASSERT_EQ(count, numAlbumArt) << "Found " << count << "album arts, expected " << numAlbumArt
                                  << "album arts! \n";
}

INSTANTIATE_TEST_SUITE_P(id3TestAll, ID3tagTest,
                         ::testing::Values("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3",
                                           "bbb_44100hz_2ch_128kbps_mp3_30sec_1_image.mp3",
                                           "bbb_44100hz_2ch_128kbps_mp3_30sec_2_image.mp3",
                                           "bbb_44100hz_2ch_128kbps_mp3_5mins.mp3",
                                           "bbb_44100hz_2ch_128kbps_mp3_5mins_1_image.mp3",
                                           "bbb_44100hz_2ch_128kbps_mp3_5mins_2_image.mp3"));

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3versionTest,
        ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3", 4),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec_1_image.mp3", 4),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec_2_image.mp3", 4),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins.mp3", 4),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins_1_image.mp3", 4),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins_2_image.mp3", 4)));

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3textTagTest,
        ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec_1_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec_2_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins_1_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins_2_image.mp3", true)));

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3albumArtTest,
        ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3", false),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec_1_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec_2_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins.mp3", false),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins_1_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins_2_image.mp3", true)));

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3multiAlbumArtTest,
        ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec_2_image.mp3", 2),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins_2_image.mp3", 2)));

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

