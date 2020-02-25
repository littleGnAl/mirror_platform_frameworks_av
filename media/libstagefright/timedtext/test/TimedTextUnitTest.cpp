/*
 * Copyright (C) 2020 The Android Open Source Project
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
#define LOG_TAG "TimedTextUnitTest"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <utils/Log.h>
#include <fstream>

#include <binder/Parcel.h>
#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/foundation/ByteUtils.h>

#include "timedtext/TextDescriptions.h"

#include "TimedTextTestEnvironment.h"

constexpr int32_t kstartTimeMs = 10000;

enum {
    // These keys must be in sync with the keys in TextDescriptions.h
    KEY_DISPLAY_FLAGS = 1,
    KEY_STYLE_FLAGS = 2,
    KEY_BACKGROUND_COLOR_RGBA = 3,
    KEY_HIGHLIGHT_COLOR_RGBA = 4,
    KEY_SCROLL_DELAY = 5,
    KEY_WRAP_TEXT = 6,
    KEY_START_TIME = 7,
    KEY_STRUCT_BLINKING_TEXT_LIST = 8,
    KEY_STRUCT_FONT_LIST = 9,
    KEY_STRUCT_HIGHLIGHT_LIST = 10,
    KEY_STRUCT_HYPER_TEXT_LIST = 11,
    KEY_STRUCT_KARAOKE_LIST = 12,
    KEY_STRUCT_STYLE_LIST = 13,
    KEY_STRUCT_TEXT_POS = 14,
    KEY_STRUCT_JUSTIFICATION = 15,
    KEY_STRUCT_TEXT = 16,

    KEY_GLOBAL_SETTING = 101,
    KEY_LOCAL_SETTING = 102,
    KEY_START_CHAR = 103,
    KEY_END_CHAR = 104,
    KEY_FONT_ID = 105,
    KEY_FONT_SIZE = 106,
    KEY_TEXT_COLOR_RGBA = 107,
};

using namespace android;

static TimedTextTestEnvironment *gEnv = nullptr;

class SRTDescriptionTest : public ::testing::TestWithParam</*filename*/ string> {};

class Text3GPPDescriptionTest : public ::testing::TestWithParam</*filename*/ string> {};

TEST_P(SRTDescriptionTest, extractSRTDescriptionTest) {
    string inputFileName = gEnv->getRes() + GetParam();
    ifstream mEleStream;
    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true) << "Failed to open " << GetParam();

    struct stat buf;
    stat(inputFileName.c_str(), &buf);
    size_t fileSize = buf.st_size;
    ALOGI("Size of the input file: %zu", fileSize);

    char data[fileSize];
    mEleStream.read(data, fileSize);

    Parcel parcel;
    int32_t flag = TextDescriptions::OUT_OF_BAND_TEXT_SRT | TextDescriptions::LOCAL_DESCRIPTIONS;
    TextDescriptions::getParcelOfDescriptions((const uint8_t *)data, fileSize, flag, kstartTimeMs,
                                              &parcel);
    ALOGI("Size of the Parcel: %zu", parcel.dataSize());
    ASSERT_NE(parcel.dataSize(), 0) << "Parcel is empty";

    parcel.setDataPosition(0);
    int32_t key = parcel.readInt32();
    ASSERT_EQ(key, KEY_LOCAL_SETTING) << "Parcel has invalid key";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_START_TIME) << "Parcel has invalid start time key";
    ASSERT_EQ(parcel.readInt32(), kstartTimeMs) << "Parcel has invalid timings";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STRUCT_TEXT) << "Parcel has invalid struct text key";
    ASSERT_EQ(parcel.readInt32(), fileSize) << "Parcel has invalid text data";

    mEleStream.close();
}

TEST_P(Text3GPPDescriptionTest, Text3GPPGlobalDescriptionTest) {
    string inputFileName = gEnv->getRes() + GetParam();
    ifstream mEleStream;
    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true) << "Failed to open " << GetParam();

    struct stat buf;
    stat(inputFileName.c_str(), &buf);
    size_t fileSize = buf.st_size;
    ALOGI("Size of the input file: %zu", fileSize);

    char data[fileSize];
    mEleStream.read(data, fileSize);

    const uint8_t *tmpData = (const uint8_t *)data;
    int32_t remaining = -1;
    int32_t displayFlag = -1;
    int32_t horizontalJustification = -1;
    int32_t verticalJustification = -1;
    uint32_t rgbaBackground = -1;
    int32_t leftPos = -1;
    int32_t topPos = -1;
    int32_t bottomPos = -1;
    int32_t rightPos = -1;
    int32_t startchar = -1;
    int32_t endChar = -1;
    int32_t fontId = -1;
    int32_t faceStyle = -1;
    int32_t fontSize = -1;
    int32_t rgbaText = -1;
    uint32_t entryCount = -1;
    int32_t fontNameLength = -1;
    const uint8_t *font;

    tmpData += 16;
    remaining = fileSize - 16;
    displayFlag = U32_AT(tmpData);
    ALOGI("Display flag: %d", displayFlag);
    horizontalJustification = tmpData[4];
    ALOGI("Horizontal Justification: %d", horizontalJustification);
    verticalJustification = tmpData[5];
    ALOGI("Vertical Justification: %d", verticalJustification);
    rgbaBackground =
            *(tmpData + 6) << 24 | *(tmpData + 7) << 16 | *(tmpData + 8) << 8 | *(tmpData + 9);
    ALOGI("rgba value of background: %d", rgbaBackground);

    tmpData += 10;
    remaining -= 10;
    if (remaining >= 8) {
        leftPos = U16_AT(tmpData);
        ALOGI("Left: %d", leftPos);
        topPos = U16_AT(tmpData + 2);
        ALOGI("Top: %d", topPos);
        bottomPos = U16_AT(tmpData + 4);
        ALOGI("Bottom: %d", bottomPos);
        rightPos = U16_AT(tmpData + 6);
        ALOGI("Right: %d", rightPos);

        tmpData += 8;
        remaining -= 8;

        if (remaining >= 12) {
            startchar = U16_AT(tmpData);
            ALOGI("Start character: %d", startchar);
            endChar = U16_AT(tmpData + 2);
            ALOGI("End character: %d", endChar);
            fontId = U16_AT(tmpData + 4);
            ALOGI("Value of font Identifier: %d", fontId);
            faceStyle = *(tmpData + 6);
            ALOGI("Face style flag : %d", faceStyle);
            fontSize = *(tmpData + 7);
            ALOGI("Size of the font: %d", fontSize);
            rgbaText = *(tmpData + 8) << 24 | *(tmpData + 9) << 16 | *(tmpData + 10) << 8 |
                       *(tmpData + 11);
            ALOGI("rgba value of the text: %d", rgbaText);

            tmpData += 12;
            remaining -= 12;

            if (remaining >= 10) {
                entryCount = U16_AT(tmpData + 8);
                ALOGI("Value of entry count: %d", entryCount);

                tmpData += 10;
                remaining -= 10;
                for (int i = 0; i < entryCount; i++) {
                    fontId = U16_AT(tmpData);
                    ALOGI("Font Id: %d", fontId);
                    fontNameLength = *(tmpData + 2);
                    ALOGI("Length of font name: %d", fontNameLength);
                    tmpData += 3;
                    remaining -= 3;
                    font = tmpData;
                    ALOGI("Font: %s", font);
                    tmpData += fontNameLength;
                    remaining -= fontNameLength;
                }
            }
        }
    }

    Parcel parcel;
    int32_t flag = TextDescriptions::IN_BAND_TEXT_3GPP | TextDescriptions::GLOBAL_DESCRIPTIONS;
    TextDescriptions::getParcelOfDescriptions((const uint8_t *)data, fileSize, flag, kstartTimeMs,
                                              &parcel);
    ALOGI("Size of the Parcel: %zu", parcel.dataSize());
    ASSERT_NE(parcel.dataSize(), 0) << "Parcel is empty";

    parcel.setDataPosition(0);
    int32_t key = parcel.readInt32();
    ASSERT_EQ(key, KEY_GLOBAL_SETTING) << "Parcel has invalid key";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_DISPLAY_FLAGS) << "Parcel has invalid DISPLAY FLAGS Key";
    ASSERT_EQ(parcel.readInt32(), displayFlag) << "Parcel has invalid value of display flag";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STRUCT_JUSTIFICATION) << "Parcel has invalid STRUCT JUSTIFICATION key";
    ASSERT_EQ(parcel.readInt32(), horizontalJustification)
            << "Parcel has invalid value of Horizontal justification";
    ASSERT_EQ(parcel.readInt32(), verticalJustification)
            << "Parcel has invalid value of Vertical justification";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_BACKGROUND_COLOR_RGBA) << "Parcel has invalid BACKGROUND COLOR key";
    ASSERT_EQ(parcel.readInt32(), rgbaBackground)
            << "Parcel has invalid rgba background color value";

    if (parcel.dataAvail() == 0) {
        mEleStream.close();
        free(data);
        return;
    }

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STRUCT_TEXT_POS) << "Parcel has invalid STRUCT TEXT POSITION key";
    ASSERT_EQ(parcel.readInt32(), leftPos) << "Parcel has invalid rgba background color value";
    ASSERT_EQ(parcel.readInt32(), topPos) << "Parcel has invalid rgba background color value";
    ASSERT_EQ(parcel.readInt32(), bottomPos) << "Parcel has invalid rgba background color value";
    ASSERT_EQ(parcel.readInt32(), rightPos) << "Parcel has invalid rgba background color value";

    if (parcel.dataAvail() == 0) {
        mEleStream.close();
        free(data);
        return;
    }

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STRUCT_STYLE_LIST) << "Parcel has invalid STRUCT STYLE LIST key";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_START_CHAR) << "Parcel has invalid START CHAR key";
    ASSERT_EQ(parcel.readInt32(), startchar) << "Parcel has invalid value of start character";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_END_CHAR) << "Parcel has invalid END CHAR key";
    ASSERT_EQ(parcel.readInt32(), endChar) << "Parcel has invalid value of end character";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_FONT_ID) << "Parcel has invalid FONT ID key";
    ASSERT_EQ(parcel.readInt32(), fontId) << "Parcel has invalid value of font Id";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STYLE_FLAGS) << "Parcel has invalid STYLE FLAGS key";
    ASSERT_EQ(parcel.readInt32(), faceStyle) << "Parcel has invalid value of style flags";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_FONT_SIZE) << "Parcel has invalid FONT SIZE key";
    ASSERT_EQ(parcel.readInt32(), fontSize) << "Parcel has invalid value of font size";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_TEXT_COLOR_RGBA) << "Parcel has invalid TEXT COLOR RGBA key";
    ASSERT_EQ(parcel.readInt32(), rgbaText) << "Parcel has invalid rgba text color value";

    if (parcel.dataAvail() == 0) {
        mEleStream.close();
        free(data);
        return;
    }

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STRUCT_FONT_LIST) << "Parcel has invalid STRUCT FONT LIST key";
    ASSERT_EQ(parcel.readInt32(), entryCount) << "Parcel has invalid value of entry count";
    ASSERT_EQ(parcel.readInt32(), fontId) << "Parcel has invalid value of font Id";
    ASSERT_EQ(parcel.readInt32(), fontNameLength) << "Parcel has invalid value of font name length";

    mEleStream.close();
}

INSTANTIATE_TEST_SUITE_P(TimedTextUnitTestAll, SRTDescriptionTest,
                         ::testing::Values(("sampleTest1.srt"),
                                           ("sampleTest2.srt")));

INSTANTIATE_TEST_SUITE_P(TimedTextUnitTestAll, Text3GPPDescriptionTest,
                         ::testing::Values(("tx3gBox1"),
                                           ("tx3gBox2")));

int main(int argc, char **argv) {
    gEnv = new TimedTextTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
