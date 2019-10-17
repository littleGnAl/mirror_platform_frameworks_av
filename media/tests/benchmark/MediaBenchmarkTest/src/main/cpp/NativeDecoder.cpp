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
#define LOG_TAG "NativeDecoder"

#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <iostream>
#include <limits>

#include <android/log.h>

#include "Decoder.h"

extern "C" JNIEXPORT void JNICALL Java_com_android_media_benchmark_library_Native_Decode(
        JNIEnv *env, jobject thiz, jstring jFilePath, jstring jFileName, jstring jCodecName,
        jboolean asyncMode) {
    const char *filePath = env->GetStringUTFChars(jFilePath, nullptr);
    const char *fileName = env->GetStringUTFChars(jFileName, nullptr);
    string sFilePath = string(filePath) + string(fileName);
    UNUSED(thiz);
    FILE *inputFp = fopen(sFilePath.c_str(), "rb");
    env->ReleaseStringUTFChars(jFileName, fileName);
    env->ReleaseStringUTFChars(jFilePath, filePath);
    if (!inputFp) {
        ALOGV("[   WARN   ] Test Skipped. Unable to open input file for reading \n");
        return;
    }

    Decoder *decoder = new Decoder();
    Extractor *extractor = decoder->getExtractor();
    if (!extractor) {
        ALOGV("[   WARN   ] Test Skipped. Extractor creation failed \n");
        return;
    }

    // Read file properties
    fseek(inputFp, 0, SEEK_END);
    size_t fileSize = ftell(inputFp);
    if (fileSize > kMaxBufferSize) {
        ALOGV("[   WARN   ] Test Skipped. File size greater than maximum buffer size ");
        return;
    }
    fseek(inputFp, 0, SEEK_SET);
    int32_t fd = fileno(inputFp);
    int32_t trackCount = extractor->initExtractor(fd, fileSize);
    if (trackCount <= 0) {
        ALOGV("[   WARN   ] Test Skipped. initExtractor failed\n");
        return;
    }
    for (int curTrack = 0; curTrack < trackCount; curTrack++) {
        int32_t status = extractor->setupTrackFormat(curTrack);
        if (status != 0) {
            ALOGV("[   WARN   ] Test Skipped. Track Format invalid \n");
            return;
        }

        uint8_t *inputBuffer = (uint8_t *)malloc(fileSize);
        if (!inputBuffer) {
            ALOGV("[   WARN   ] Test Skipped. Insufficient memory \n");
            return;
        }

        vector<AMediaCodecBufferInfo> frameInfo;
        AMediaCodecBufferInfo info;
        uint32_t inputBufferOffset = 0;

        // Get frame data
        while (1) {
            status = extractor->getFrameSample(info);
            if (status || !info.size) break;
            // copy the meta data and buffer to be passed to decoder
            if (inputBufferOffset + info.size > kMaxBufferSize) {
                ALOGV("[   WARN   ] Test Skipped. Memory allocated not sufficient\n");
                free(inputBuffer);
                return;
            }
            memcpy(inputBuffer + inputBufferOffset, extractor->getFrameBuf(), info.size);
            frameInfo.push_back(info);
            inputBufferOffset += info.size;
        }

        const char *codecName = env->GetStringUTFChars(jCodecName, nullptr);
        string sCodecName = string(codecName);
        decoder->setupDecoder();
        status = decoder->decode(inputBuffer, frameInfo, sCodecName, asyncMode);
        if (status != AMEDIA_OK) {
            ALOGV("[   WARN   ] Test Skipped. Decode returned error \n");
            free(inputBuffer);
            env->ReleaseStringUTFChars(jCodecName, codecName);
            return;
        }
        decoder->deInitCodec();
        env->ReleaseStringUTFChars(jCodecName, codecName);
        const char *inputReference = env->GetStringUTFChars(jFileName, nullptr);
        string sInputReference = string(inputReference);
        decoder->dumpStatistics(sInputReference);
        env->ReleaseStringUTFChars(jFileName, inputReference);
        free(inputBuffer);
        decoder->resetDecoder();
    }
    fclose(inputFp);
    extractor->deInitExtractor();
    delete decoder;
}
