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

/****************************************************************************************/
/*                                                                                      */
/*    Includes                                                                          */
/*                                                                                      */
/****************************************************************************************/

#include "PreProcessingCorr.h"
#define OUT_LOOP_LIMIT 0

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                  xCorr                                                     */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    Compute the correlation of two signals                                            */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  sigX                   Pointer to signal 1                                          */
/*  sigY                   Pointer to signal 2                                          */
/*  len                    Length of signals                                            */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  int                    Max correlation value index                                  */
/*                                                                                      */
/****************************************************************************************/

static int xCorr(short* sigX, short* sigY, int len, float* pMaxCorrVal) {
    float maxCorrVal = 0.0f;
    int delay = 0;
    float corrVal = 0.0f;
    int i, j;
#ifdef ENABLE_CROSS_CORR
    for (i = 0; i < len; i++) {
#else
    for (i = 0; i <= OUT_LOOP_LIMIT; i++) {
#endif
        corrVal = 0.0f;
        for (j = i; j < len; j++) {
            corrVal = corrVal + ((float)sigX[j] / 32768.f) * ((float)(sigY[j - i]) / 32768.f);
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
    printf("\n     correlationTest <first_file> <second_file> <length>\n");
    printf("\nwhere, \n     <first_file>  is the first file name");
    printf("\n     <second_file> is second file for correlation calculation\n\n");
}

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        printUsage();
        return -1;
    }

    int ret = EXIT_SUCCESS;
    FILE* finp = fopen(argv[1], "rb");
    FILE* fout = fopen(argv[2], "rb");
    if (finp == nullptr || fout == nullptr) {
        printf("\nError: missing files\n");
        return -1;
    }

    fseek(finp, 0L, SEEK_END);
    unsigned int fileSize = ftell(finp);
    rewind(finp);

    short* inBuffer = (short*)malloc(fileSize / sizeof(short));
    short* outBuffer = (short*)malloc(fileSize / sizeof(short));

    if (finp) {
        fread(inBuffer, sizeof(short), fileSize / sizeof(short), finp);
        fclose(finp);
        finp = NULL;
    }
    if (fout) {
        fread(outBuffer, sizeof(short), fileSize / sizeof(short), fout);
        fclose(fout);
        fout = NULL;
    }

    float maxAutoCorrIn = 0.0f, maxAutoCorrOut = 0.0f;
    int delay_autocorr_in = xCorr(inBuffer, inBuffer, fileSize / sizeof(short), &maxAutoCorrIn);
    int delay_autocorr_out = xCorr(outBuffer, outBuffer, fileSize / sizeof(short), &maxAutoCorrOut);
    if (delay_autocorr_in != delay_autocorr_out) {
        printf("Pitch mismatch : delay_autocorr_in %d | delay_autocorr_out %d\n", delay_autocorr_in,
               delay_autocorr_out);
    } else {
        printf("Pitch matching\n");
    }

#ifdef ENABLE_CROSS_CORR
    float maxCrossCorr = 0.0f;
    int delay_crosscorr = xCorr(inBuffer, outBuffer, fileSize / sizeof(short), &maxCrossCorr);

    if (delay_autocorr_in != delay_crosscorr) {
        printf("Pitch mismatch : delay_autocorr_in %d | delay_crosscorr %d\n", delay_autocorr_in,
               delay_crosscorr);
    } else {
        printf("Pitch matching\n");
        printf("Expected gain : (maxCrossCorr / maxAutoCorrIn) = %f\n",
               maxCrossCorr / maxAutoCorrIn);
    }
#endif

    if (inBuffer) {
        free(inBuffer);
        inBuffer = NULL;
    }
    if (outBuffer) {
        free(outBuffer);
        outBuffer = NULL;
    }
    return ret;
}
