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

#include <iostream>

constexpr int kMinLoopLimitValue = 1;
constexpr float kMaxInputValueSquared = 32768.f * 32768.f;

/*!
  \brief           Compute the correlation of two signals

  \sigX            Pointer to signal 1
  \sigY            Pointer to signal 2
  \len             Length of signals
  \enableCrossCorr Flag to be set to 1 if cross-correlation is needed

  \return          std::pair<int, float>
*/

static std::pair<int, float> correlation(const int16_t* sigX, const int16_t* sigY, int len,
                                         int16_t enableCrossCorr) {
    float maxCorrVal = 0.f;
    int delay = 0;
    int loopLim = (1 == enableCrossCorr) ? len : kMinLoopLimitValue;
    for (int i = 0; i < loopLim; i++) {
        float corrVal = 1e-10;  // To handle silence frames
        for (int j = i; j < len; j++) {
            corrVal = corrVal + (float)(sigX[j] * sigY[j - i]);
        }
        if (corrVal > maxCorrVal) {
            delay = i;
            maxCorrVal = corrVal;
        }
    }
    return {delay, maxCorrVal / kMaxInputValueSquared};
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

    auto pairAutoCorr1 = correlation(inBuffer1.get(), inBuffer1.get(), numFrames, enableCrossCorr);
    auto pairAutoCorr2 = correlation(inBuffer2.get(), inBuffer2.get(), numFrames, enableCrossCorr);
    if (pairAutoCorr1.first != pairAutoCorr2.first) {
        printf("Pitch mismatch    : delayAutoCorr1 %d | delayAutoCorr2 %d\n", pairAutoCorr1.first,
               pairAutoCorr2.first);
        return EXIT_FAILURE;
    } else {
        printf("Auto-correlation  : Pitch matching : maxAutoCorr1 %f | maxAutoCorr2 %f\n",
               pairAutoCorr1.second, pairAutoCorr2.second);
    }

    if (enableCrossCorr) {
        auto pairCrossCorr =
                correlation(inBuffer1.get(), inBuffer2.get(), numFrames, enableCrossCorr);

        if (pairAutoCorr1.first != pairCrossCorr.first) {
            printf("Pitch mismatch    : delayAutoCorr1 %d | delayCrossCorr %d\n",
                   pairAutoCorr1.first, pairCrossCorr.first);
            return EXIT_FAILURE;
        } else {
            printf("Cross-correlation : Pitch matching\n");
            printf("Expected gain     : (maxCrossCorr / maxAutoCorr1) = %f\n",
                   pairCrossCorr.second / pairAutoCorr1.second);
        }
    }

    return EXIT_SUCCESS;
}
