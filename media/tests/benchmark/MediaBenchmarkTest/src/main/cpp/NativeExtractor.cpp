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
#define LOG_TAG "NativeExtractor"

#include <jni.h>
#include <string>
#include <stdio.h>

#include "Extractor.h"
#include "Stats.h"

extern "C"
JNIEXPORT int32_t JNICALL
Java_com_android_media_benchmark_library_Native_Extract(JNIEnv *env, jobject thiz,
                                                        jstring jInputFilePath,
                                                        jstring jInputFileName) {
    UNUSED(thiz);
    const char *inputFilePath = env->GetStringUTFChars(jInputFilePath, nullptr);
    const char *inputFileName = env->GetStringUTFChars(jInputFileName, nullptr);
    string sFilePath = string(inputFilePath) + string(inputFileName);
    FILE *inputFp = fopen(sFilePath.c_str(), "rb");
    fseek(inputFp, 0, SEEK_END);
    auto fileSize = static_cast<size_t>(ftell(inputFp));
    fseek(inputFp, 0, SEEK_SET);
    int32_t fd = fileno(inputFp);
    Extractor *extractObj = new Extractor();
    int32_t trackCount = extractObj->initExtractor((long) fd, fileSize);
    if (trackCount <= 0) {
        ALOGV("[   WARN   ] Test Skipped. initExtractor failed\n");
        return -1;
    }

    int32_t trackID = 0;
    int32_t status = extractObj->extract(trackID);
    if (status != AMEDIA_OK) {
        ALOGV("[   WARN   ] Test Skipped. Extraction failed\n");
        return -1;
    }
    extractObj->deInitExtractor();
    extractObj->dumpStatistics(inputFileName);

    env->ReleaseStringUTFChars(jInputFilePath, inputFilePath);
    env->ReleaseStringUTFChars(jInputFileName, inputFileName);

    delete extractObj;
    return status;
}
