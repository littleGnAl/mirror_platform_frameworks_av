/*
 * Copyright (C) 2004-2010 NXP Software
 * Copyright (C) 2010 The Android Open Source Project
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

/**********************************************************************************
   INCLUDE FILES
***********************************************************************************/
#include "ScalarArithmetic.h"
#include "VectorArithmetic.h"
#include <log/log.h>
#include <math.h>
void Add2_Sat_Float(const LVM_FLOAT* src, LVM_FLOAT* dst, LVM_INT16 n) {
    LVM_FLOAT Temp;
    LVM_INT16 ii;
    for (ii = n; ii != 0; ii--) {
        Temp = *src++ + *dst;
        *dst++ = LVM_Clamp(Temp);
    }
    return;
}

void dumpData(const char* name, void* buf, size_t numBytes) {
    if (FILE* fp = fopen(name, "ab")) {
        ALOGD("Writing to to %s", name);
        fwrite(buf, sizeof(uint8_t), numBytes, fp);
        fclose(fp);
    } else {
        ALOGE("Unable to write output to %s", name);
    }
}

void printAvgAmpliture(const char* name, LVM_FLOAT* buf, size_t numSamples) {
    float sum = 0.0;
    for (size_t i = 0; i < numSamples; i++) {
        sum += fabs(buf[i]);
    }
    ALOGD("average amplitude of %s : %f/%zu -> %f", name, sum, numSamples, sum / numSamples);
}
