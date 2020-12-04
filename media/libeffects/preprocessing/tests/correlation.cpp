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

/****************************************************************************************/
/*                                                                                      */
/*    Includes                                                                          */
/*                                                                                      */
/****************************************************************************************/

#include <iostream>

constexpr int kMinLoopLimitValue = 1;
constexpr float kMaxInputValue = 32768.f;

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:               correlation                                                  */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    Compute the correlation of two signals                                            */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  sigX                   Pointer to signal 1                                          */
/*  sigY                   Pointer to signal 2                                          */
/*  len                    Length of signals                                            */
/*  pMaxCorrVal            Pointer to Maximum value of correlation                      */
/*  enableCrossCorr        Flag to be set to 1 if cross-correlation is needed           */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  int                    Max correlation value index                                  */
/*                                                                                      */
/****************************************************************************************/

static int correlation(int16_t* sigX, int16_t* sigY, int len, float* pMaxCorrVal,
                       int16_t enableCrossCorr) {
    float maxCorrVal = 1e-10;  // To handle silence frames
    int delay = 0;
    float corrVal = 1e-10;  // To handle silence frames
    int loopLim = (1 == enableCrossCorr) ? len : kMinLoopLimitValue;
    for (int i = 0; i < loopLim; i++) {
        corrVal = 1e-10;  // To handle silence frames
        for (int j = i; j < len; j++) {
            corrVal = corrVal +
                      ((float)sigX[j] / kMaxInputValue) * ((float)(sigY[j - i]) / kMaxInputValue);
        }
        if (corrVal > maxCorrVal) {
            delay = i;
            maxCorrVal = corrVal;
        }
    }
    *pMaxCorrVal = maxCorrVal;
    return delay;
}

void printUsage() {
    printf("\nUsage: ");
    printf("\n     correlation <firstFile> <secondFile> [enableCrossCorr]\n");
    printf("\nwhere, \n     <firstFile>       is the first file name");
    printf("\n     <secondFile>      is the second file name");
    printf("\n     [enableCrossCorr] is flag to set for cross-correlation (Default 1)\n\n");
}

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        printUsage();
        return EXIT_FAILURE;
    }

    std::unique_ptr<FILE, decltype(&fclose)> fInput1(fopen(argv[1], "rb"), &fclose);
    if (fInput1.get() == NULL) {
        printf("\nError: missing file %s\n", argv[1]);
        return EXIT_FAILURE;
    }
    std::unique_ptr<FILE, decltype(&fclose)> fInput2(fopen(argv[2], "rb"), &fclose);
    if (fInput2.get() == NULL) {
        printf("\nError: missing file %s\n", argv[2]);
        return EXIT_FAILURE;
    }
    int16_t enableCrossCorr = (4 == argc) ? atoi(argv[3]) : 1;

    fseek(fInput1.get(), 0L, SEEK_END);
    unsigned int fileSize1 = ftell(fInput1.get());
    rewind(fInput1.get());
    fseek(fInput2.get(), 0L, SEEK_END);
    unsigned int fileSize2 = ftell(fInput2.get());
    rewind(fInput2.get());
    if (fileSize1 != fileSize2) {
        printf("\nError: File sizes different\n");
        return EXIT_FAILURE;
    }

    int numFrames = fileSize1 / sizeof(int16_t);
    std::unique_ptr<int16_t[]> inBuffer1(new int16_t[numFrames]());
    std::unique_ptr<int16_t[]> inBuffer2(new int16_t[numFrames]());

    fread(inBuffer1.get(), sizeof(int16_t), numFrames, fInput1.get());
    fread(inBuffer2.get(), sizeof(int16_t), numFrames, fInput2.get());

    float maxAutoCorr1 = 0.0f, maxAutoCorr2 = 0.0f;
    int delayAutoCorr1 = correlation(inBuffer1.get(), inBuffer1.get(), numFrames, &maxAutoCorr1,
                                     enableCrossCorr);
    int delayAutoCorr2 = correlation(inBuffer2.get(), inBuffer2.get(), numFrames, &maxAutoCorr2,
                                     enableCrossCorr);
    if (delayAutoCorr1 != delayAutoCorr2) {
        printf("Pitch mismatch    : delayAutoCorr1 %d | delayAutoCorr2 %d\n", delayAutoCorr1,
               delayAutoCorr2);
    } else {
        printf("Auto-correlation  : Pitch matching : maxAutoCorr1 %f | maxAutoCorr2 %f\n",
               maxAutoCorr1, maxAutoCorr2);
    }

    if (enableCrossCorr) {
        float maxCrossCorr = 0.0f;
        int delayCrossCorr = correlation(inBuffer1.get(), inBuffer2.get(), numFrames, &maxCrossCorr,
                                         enableCrossCorr);

        if (delayAutoCorr1 != delayCrossCorr) {
            printf("Pitch mismatch    : delayAutoCorr1 %d | delayCrossCorr %d\n", delayAutoCorr1,
                   delayCrossCorr);
        } else {
            printf("Cross-correlation : Pitch matching\n");
            printf("Expected gain     : (maxCrossCorr / maxAutoCorr1) = %f\n",
                   maxCrossCorr / maxAutoCorr1);
        }
    }

    return EXIT_SUCCESS;
}
