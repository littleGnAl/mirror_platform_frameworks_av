/*
 * Copyright (C) 2014 The Android Open Source Project
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
/*****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
/*!
 **************************************************************************/
/*!
 **************************************************************************
 * \file grainBlending_test.cpp
 *
 * \brief
 *    Contains sample application to demonstrate use of grain blending APIs
 *
 * \date
 *    14/09/2021
 *
 * \author  NS
 **************************************************************************
 */

#include <assert.h>
#include <getopt.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <regex>

#include "grainBlending.h"

using namespace std;
using namespace android;

#define ENABLE_VIDEO_WRITE 1

#define MAX_QUEUE_NAME_SIZE 64
#define MAX_STRING_LENGTH 4096
#define MAX_LOG_LENGTH MAX_STRING_LENGTH

#define UNIT_APP_MAX_LINE_LEN 1024
#define UNIT_APP_MAX_NUM_PARAM 30
#define UNIT_APP_MAX_PARAM_LEN 1024
#define MAX_FILE_NAME_STR_SIZE 1024

/*---------------------------------------------------------------------------*/
/*                           Structure Definitions                           */
/*---------------------------------------------------------------------------*/

/* Film Grain Synthesizer application context */
typedef struct fgs_app_params_t {
    /* Frame num from FGC params are applicable*/
    uint32_t startFrameNum;
    /* Frame num till FGC params are applicable*/
    uint32_t endFrameNum;
    /* Total number of frames to be processed */
    uint32_t numFrames;
    /* Configuration file */
    char initParamsCfgFile[MAX_LOG_LENGTH];
    /* Input YUV file name */
    char inputFileName[MAX_LOG_LENGTH];
    /* Output YUV file name */
    char outputFile[MAX_LOG_LENGTH];
    /* Input width */
    uint32_t frameWidth;
    /* Input height */
    uint32_t frameHeight;
    /* Input bit depth */
    uint8_t bitDepth;
    /* Input chroma format */
    uint8_t chromaFmt;
    /* Number of threads*/
    int32_t numThreads;
    /* Set processor architecture*/
    uint32_t processorArch;
} fgs_app_params;

static struct option long_options[] = {
    {"input_file", required_argument, NULL, 'i'},
    {"output_file", required_argument, NULL, 'o'},
    {"num_frames", required_argument, NULL, 'f'},
    {"width", required_argument, NULL, 'w'},
    {"height", required_argument, NULL, 'h'},
    {"bit_depth", required_argument, NULL, 'b'},
    {"chroma_format", required_argument, NULL, 'c'},
    {"num_threads", required_argument, NULL, 't'},
    {"processor_arch", required_argument, NULL, 'p'},
    {NULL, 0, NULL, 0}};

static struct option long_options_fgc[] = {
    {"start_frame_num", required_argument, NULL, 't'},
    {"end_frame_num", required_argument, NULL, 'e'},
    {"film_grain_characteristics_cancel_flag", required_argument, NULL, 'f'},
    {"log2_scale_factor", required_argument, NULL, 's'},
    {"block_size", required_argument, NULL, 'b'},
    {"disable_fgs_chroma", required_argument, NULL, 'c'},
    {"comp_model_present_flag", required_argument, NULL, 'p'},
    {"num_intensity_intervals_minus1", required_argument, NULL, 'n'},
    {"intensity_interval_lower_bound", required_argument, NULL, 'l'},
    {"intensity_interval_upper_bound", required_argument, NULL, 'u'},
    {"num_model_values_minus1", required_argument, NULL, 'm'},
    {"comp_model_value", required_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}};

uint32_t getProcessorArch(const char *arch) {
    if (!strcmp(arch, "ARCH_ARM_GENERIC"))
        return ARCH_ARM_GENERIC;
    else if (!strcmp(arch, "ARCH_ARMV8_INTRINSICS"))
        return ARCH_ARMV8_INTRINSICS;
    else if (!strcmp(arch, "ARCH_X86_GENERIC"))
        return ARCH_ARM_GENERIC;
    else if (!strcmp(arch, "ARCH_X86_SSE42_INTRINSICS"))
        return ARCH_X86_SSE42_INTRINSICS;
    else {
        cout << "\nInvalid Arch. Setting it to ARCH_ARM_GENERIC" << endl;
        return ARCH_ARM_GENERIC;
    }
}

void getCfgFileTokens(ifstream &file, string startMarker, string endMarker,
                      char tokenString[][UNIT_APP_MAX_LINE_LEN], char *tokenWords[],
                      int *numTokens) {
    
    int startFlag = 0;
    regex input_start{"\\s*" + startMarker + "\\s*"};
    regex input_end{"\\s*" + endMarker + "\\s*"};
    regex blankLine{"^\\s*$"};
    int curLine = 0;

    *numTokens = 1;
    tokenWords[0] = NULL;

    while (file.getline(tokenString[curLine], UNIT_APP_MAX_LINE_LEN)) {

        /* Blank and empty lines */
        if (tokenString[curLine][0] == '#' || regex_match(tokenString[curLine], blankLine)) {
            continue;
        }
        if (!startFlag) {
            if (!regex_match(tokenString[curLine], input_start))
                continue;
            else
                startFlag = 1;
            continue;
        }

        if (regex_match(tokenString[curLine], input_end))
            break;

        tokenWords[*numTokens] = strtok(tokenString[curLine], " \t");
        curLine++;

        while (tokenWords[*numTokens] != NULL) {
            (*numTokens)++;
            tokenWords[*numTokens] = strtok(NULL, " \t");
        }
    }
}

void parseInputParams(ifstream &file, fgs_app_params *fgsAppParams) {
    signed char opt;
    optind = 0;
    char elementArr[UNIT_APP_MAX_NUM_PARAM][UNIT_APP_MAX_LINE_LEN];
    char *fargv[UNIT_APP_MAX_NUM_PARAM];
    int fargc = 1;
    int curLine = 0;
    int startFlag = 0;
    regex input_start{"\\s*INPUT_PARAMS_START\\s*"};
    regex input_end{"\\s*INPUT_PARAMS_END\\s*"};
    regex blankLine{"^\\s*$"};
    string inputStartMarker{"INPUT_PARAMS_START"};
    string inputEndMarker{"INPUT_PARAMS_END"};

    getCfgFileTokens(file, inputStartMarker, inputEndMarker,elementArr, fargv, &fargc);

    while ((opt = getopt_long(fargc, fargv, "i:o:w:h:f:b:c:t:p:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                strcpy(fgsAppParams->inputFileName, optarg);
                break;
            case 'o':
                strcpy(fgsAppParams->outputFile, optarg);
                break;
            case 'w':
                fgsAppParams->frameWidth = atoi(optarg);
                break;
            case 'h':
                fgsAppParams->frameHeight = atoi(optarg);
                break;
            case 'f':
                fgsAppParams->numFrames = atoi(optarg);
                break;
            case 'b':
                fgsAppParams->bitDepth = (uint8_t)(atoi(optarg));
                break;
            case 'c':
                fgsAppParams->chromaFmt = (uint8_t)atoi(optarg);
                break;
            case 't':
                fgsAppParams->numThreads = atoi(optarg);
                break;
            case 'p':
                fgsAppParams->processorArch = getProcessorArch(optarg);
                break;
            default:
                cout << "unrecognised option" << optarg << endl;
                break;
        }
    }
}

template <typename T>
void extractElements(string str, vector<T> &elements, int maxNumElements) {
    T a;
    str.erase(remove(str.begin(), str.end(), ' '), str.end());
    stringstream ss(str);
    elements.clear();
    while ((ss >> a) && (elements.size() < maxNumElements)) {
        elements.push_back(a);

        if (ss.peek() == ',') ss.ignore();
    }
}

int32_t parseFGCParams(ifstream &file, fgs_app_params *fgsAppParams,
                       FilmGrainCharacteristicsStruct *psFgcParameters) {
    signed char opt;
    vector<int32_t> vecCompValsPresent;
    vector<int32_t> vecCompModelVals;
    vector<int32_t> vecNumIntensityIntervals;
    vector<int32_t> vecNumModelVal;
    vector<int32_t> vecIntLowLimit;
    vector<int32_t> vecIntUppLimit;
    optind = 0;

    char elementArr[UNIT_APP_MAX_NUM_PARAM][UNIT_APP_MAX_LINE_LEN];
    char *fargv[UNIT_APP_MAX_NUM_PARAM];
    int fargc;
    
    string fgcStartMarker{"FGC_PARAMS_PROFILE_START"};
    string fgcEndMarker{"FGC_PARAMS_PROFILE_END"};

    getCfgFileTokens(file, fgcStartMarker, fgcEndMarker,elementArr, fargv, &fargc);

    while ((opt = getopt_long(fargc, fargv, "t:e:f:s:b:c:p:n:l:u:m:v:", long_options_fgc, NULL)) !=
           -1) {
        switch (opt) {
            case 't':
                fgsAppParams->startFrameNum = atoi(optarg);
                break;
            case 'e':
                fgsAppParams->endFrameNum = atoi(optarg);
                break;
            case 'f':
                psFgcParameters->filmGrainCharacteristicsCancelFlag = atoi(optarg);
                break;
            case 's':
                psFgcParameters->log2ScaleFactor = atoi(optarg);
                break;
            case 'b':
                psFgcParameters->blockSize = atoi(optarg);
                break;
            case 'c':
                psFgcParameters->disableFGSforChroma = atoi(optarg);
                break;
            case 'p':
                extractElements<int32_t>(optarg, vecCompValsPresent, FGS_MAX_NUM_COMP);
                break;
            case 'n':
                extractElements<int32_t>(optarg, vecNumIntensityIntervals, FGS_MAX_NUM_COMP);
                break;
            case 'l':
                extractElements<int32_t>(optarg, vecIntLowLimit,
                                         FGS_MAX_NUM_COMP * FGS_MAX_NUM_INTENSITIES);
                break;
            case 'u':
                extractElements<int32_t>(optarg, vecIntUppLimit,
                                         FGS_MAX_NUM_COMP * FGS_MAX_NUM_INTENSITIES);
                break;
            case 'm':
                extractElements<int32_t>(optarg, vecNumModelVal, FGS_MAX_NUM_COMP);
                break;
            case 'v':
                extractElements<int32_t>(
                    optarg, vecCompModelVals,
                    FGS_MAX_NUM_COMP * FGS_MAX_NUM_INTENSITIES * FGS_MAX_NUM_COMP);
                break;
            default:
                cout << "unrecognised option" << optarg << endl;
                break;
        }
    }

    for (int c = 0; c < FGS_MAX_NUM_COMP; c++) {
        if (c < vecCompValsPresent.size())
            psFgcParameters->compModelPresentFlag[c] = vecCompValsPresent[c];
        else {
            return FAILURE_RET;
        }
    }

    int idx1 = 0;
    int idx2 = 0;
    int idx3 = 0;

    for (int c = 0; c < FGS_MAX_NUM_COMP; c++) {
        if (psFgcParameters->compModelPresentFlag[c]) {
            if (idx1 < vecNumIntensityIntervals.size() && idx1 < vecNumModelVal.size()) {
                psFgcParameters->numIntensityIntervalsMinus1[c] = vecNumIntensityIntervals[idx1];
                psFgcParameters->numModelValuesMinus1[c] = vecNumModelVal[idx1];
                idx1++;
            } else {
                return FAILURE_RET;
            }

            for (int i = 0; i <= psFgcParameters->numIntensityIntervalsMinus1[c]; i++) {
                if ((idx2 < vecIntLowLimit.size()) && (idx2 < vecIntUppLimit.size())) {
                    psFgcParameters->intensityIntervalLowerBound[c][i] = vecIntLowLimit[idx2];
                    psFgcParameters->intensityIntervalUpperBound[c][i] = vecIntUppLimit[idx2];
                    idx2++;
                } else {
                    return FAILURE_RET;
                }

                for (int j = 0; j <= psFgcParameters->numModelValuesMinus1[c]; j++) {
                    if (idx3 < vecCompModelVals.size()) {
                        psFgcParameters->compModelValue[c][i][j] = vecCompModelVals[idx3];
                        idx3++;
                    }
                }
            }
        }
    }
    
    /* Default and only supported value for these parameters */
    psFgcParameters->filmGrainModelId = 0;
    psFgcParameters->blendingModeId = 0;
    psFgcParameters->separateColourDescriptionPresentFlag = 0;
    psFgcParameters->filmGrainCharacteristicsRepetitionPeriod = 0;
    
    /*Print parsed parameters */
    printf("\n------------------ FGC Params Start ------------------\n\n");
    printf("start_frame_num : %d\n", fgsAppParams->startFrameNum);
    printf("end_frame_num : %d\n", fgsAppParams->endFrameNum);
    printf("film_grain_characteristics_cancel_flag : %d\n",
            psFgcParameters->filmGrainCharacteristicsCancelFlag);
    printf("log2_scale_factor : %d\n", psFgcParameters->log2ScaleFactor);
    printf("block_size : %d\n", psFgcParameters->blockSize);
    printf("disable_fgs_chroma : %d\n", psFgcParameters->disableFGSforChroma);
    printf("comp_model_present_flag : ");
    for (int c = 0; c < 3; c++) {
        printf("%d ", psFgcParameters->compModelPresentFlag[c]);
    }
    printf("\n");
    printf("num_intensity_intervals_minus1 : ");
    for (int c = 0; c < FGS_MAX_NUM_COMP; c++) {
        if (psFgcParameters->compModelPresentFlag[c]) {
            printf("%d ", psFgcParameters->numIntensityIntervalsMinus1[c]);
        }
    }
    printf("\n");
    printf("num_model_values_minus1 : ");
    for (int c = 0; c < FGS_MAX_NUM_COMP; c++) {
        if (psFgcParameters->compModelPresentFlag[c]) {
            printf("%d ", psFgcParameters->numModelValuesMinus1[c]);
        }
    }
    printf("\n");
    printf("intensity_interval_lower_bound : ");
    for (int c = 0; c < FGS_MAX_NUM_COMP; c++) {
        if (psFgcParameters->compModelPresentFlag[c]) {
            for (int i = 0; i <= psFgcParameters->numIntensityIntervalsMinus1[c]; i++) {
                printf("%d ", psFgcParameters->intensityIntervalUpperBound[c][i]);
            }
        }
    }
    printf("\n");
    printf("intensity_interval_upper_bound : ");
    for (int c = 0; c < FGS_MAX_NUM_COMP; c++) {
        if (psFgcParameters->compModelPresentFlag[c]) {
            for (int i = 0; i <= psFgcParameters->numIntensityIntervalsMinus1[c]; i++) {
                printf("%d ", psFgcParameters->intensityIntervalLowerBound[c][i]);
            }
        }
    }
    printf("\n");
    printf("comp_model_value : ");
    for (int c = 0; c < FGS_MAX_NUM_COMP; c++) {
        if (psFgcParameters->compModelPresentFlag[c]) {
            for (int i = 0; i <= psFgcParameters->numIntensityIntervalsMinus1[c]; i++) {
                for (int j = 0; j <= psFgcParameters->numModelValuesMinus1[i]; j++) {
                    printf("%d ", psFgcParameters->compModelValue[c][i][j]);
                }
            }
        }
    }
    printf("\n");
    printf("\n------------------ FGC Params End --------------------\n\n");

    return SUCCESS_RET;
}

/* Main function */
int main(int argc, char *argv[]) {
    int32_t status = 0, bytesRead;
    int32_t sizeInBytes = 0;
    uint32_t frameNum = 0;
    FILE *outputFile = NULL;
    uint8_t *pdecPelFrm;
    FILE *inputFile; /* Input YUV file pointer */
    void *psFgsHandle;
    fgs_app_params *psFgsAppParams = (fgs_app_params *)malloc(sizeof(fgs_app_params));
    GrainCharacteristicApi fgcCTx = {0};
    int8_t height_shift, width_shift;

    if (NULL == psFgsAppParams) {
        printf("[Error] Failed to allocate memory\n");
        return FAILURE_RET;
    }
    if (2 != argc) {
        printf("[ERROR] Invalid number of arguments, %d provided\n", argc);
        printf("Example: ./fgs_app.out fgs_config.txt\n");
        return FAILURE_RET;
    }

    strcpy(psFgsAppParams->initParamsCfgFile, argv[1]);
    /* Parse and validate init params from file */
    ifstream cfgFile{psFgsAppParams->initParamsCfgFile};

    if (!cfgFile.is_open()) {
        printf("Failed to open configuration file: %s\n", psFgsAppParams->initParamsCfgFile);
        return FAILURE_RET;
    }

    /* Parse Input Params from Config File */
    parseInputParams(cfgFile, psFgsAppParams);

    printf("\n------------------ Input params Start ------------------\n\n");
    printf("input_file : %s\n", psFgsAppParams->inputFileName);
    printf("output_file : %s\n", psFgsAppParams->outputFile);
    printf("num_frames : %d\n", psFgsAppParams->numFrames);
    printf("width : %d\n", psFgsAppParams->frameWidth);
    printf("height : %d\n", psFgsAppParams->frameHeight);
    printf("bit_depth : %d\n", psFgsAppParams->bitDepth);
    printf("chroma_format : %d\n", psFgsAppParams->chromaFmt);
    printf("num_threads : %d\n", psFgsAppParams->numThreads);
    printf("processor_arch : %d\n", psFgsAppParams->processorArch);
    printf("\n------------------ Input params End ------------------\n\n");
    
    fgcCTx.width = psFgsAppParams->frameWidth;
    fgcCTx.height = psFgsAppParams->frameHeight;
    fgcCTx.bitDepth = psFgsAppParams->bitDepth;
    fgcCTx.chromaFormat = psFgsAppParams->chromaFmt;

    if (1 == fgcCTx.chromaFormat)    
    {
        /* 420 */
        sizeInBytes = (psFgsAppParams->frameWidth * psFgsAppParams->frameHeight * 3) >> 1;
        height_shift = 1;
        width_shift = 1;
    } else if (2 == fgcCTx.chromaFormat)
    {
        /* 422 */
        sizeInBytes = (psFgsAppParams->frameWidth * psFgsAppParams->frameHeight) << 1;
        height_shift = 0;
        width_shift = 1;
    } else if (3 == fgcCTx.chromaFormat)
    {
        /* 444 */
        sizeInBytes = (psFgsAppParams->frameWidth * psFgsAppParams->frameHeight * 3);
        height_shift = 0;
        width_shift = 0;
    } else if (0 == fgcCTx.chromaFormat)
    {
        /* Monochrome */
        sizeInBytes = (psFgsAppParams->frameWidth * psFgsAppParams->frameHeight);
    } else {
        assert(0);
    }

    sizeInBytes = sizeInBytes * ((fgcCTx.bitDepth + 7) / 8);

    /* Init call to generate handlew with data base */
    FGSInitParams initParams;
    initParams.maxWidth = psFgsAppParams->frameWidth;
    initParams.maxHeight = psFgsAppParams->frameHeight;
    initParams.maxbitDepth = psFgsAppParams->bitDepth;
    initParams.numThreads = psFgsAppParams->numThreads;
    initParams.processorArch = psFgsAppParams->processorArch;

    /* Init call to generate handlew with data base */
    psFgsHandle = fgs_create(&initParams);

    /* Open input and output files */
    inputFile = fopen(psFgsAppParams->inputFileName, "rb");
    outputFile = fopen(psFgsAppParams->outputFile, "wb+");

    if (!inputFile) {
        printf("Failed to open input yuv %s\n", psFgsAppParams->inputFileName);
        return FAILURE_RET;
    }

    if (!outputFile) {
        printf("Failed to open output yuv %s\n", psFgsAppParams->outputFile);
        return FAILURE_RET;
    }
    /* Allocate memory for frame level buf */
    pdecPelFrm = (uint8_t *)malloc(sizeof(uint8_t) * sizeInBytes);

    /* Start configuration file parsing, Exit on reaching the end of file */
    while (1) {
        if (cfgFile.peek() == EOF) {
            while ((frameNum < psFgsAppParams->numFrames)) {
                bytesRead = fread(pdecPelFrm, sizeInBytes, sizeof(uint8_t), inputFile);
                if (!bytesRead) {
                    printf("Reached end of input file\n");
                    break;
                }
                frameNum++;
#if ENABLE_VIDEO_WRITE
                fwrite(pdecPelFrm, sizeInBytes, sizeof(uint8_t), outputFile);
#endif
            }
            break;
        } else {
            uint32_t i, j, c;
            status = parseFGCParams(cfgFile, psFgsAppParams, &(fgcCTx.fgcParameters));

            
            if (SUCCESS_RET != status) {
                printf("Failed to parse configuration file: %s\n",
                       psFgsAppParams->initParamsCfgFile);
                return FAILURE_RET;
            }

            if (psFgsAppParams->startFrameNum >= frameNum) {
                if (psFgsAppParams->startFrameNum > frameNum) {
                    while ((frameNum < psFgsAppParams->startFrameNum) &&
                           (frameNum < psFgsAppParams->numFrames)) {
                        bytesRead = fread(pdecPelFrm, sizeInBytes, sizeof(uint8_t), inputFile);
                        if (!bytesRead) {
                            printf("Reached end of input file\n");
                            break;
                        }
                        frameNum++;
#if ENABLE_VIDEO_WRITE
                        fwrite(pdecPelFrm, sizeInBytes, sizeof(uint8_t), outputFile);
#endif
                    }
                }
                int16_t buf_offset_val = 1;
                if (fgcCTx.bitDepth > 8) {
                    buf_offset_val = 1;
                }
                /* Interface b/w App and Lib START */
                while ((frameNum < psFgsAppParams->endFrameNum) &&
                       (frameNum < psFgsAppParams->numFrames)) {
                    fgcCTx.poc = frameNum % 256;
                    fgcCTx.idrPicId = 0;
                    bytesRead = fread(pdecPelFrm, sizeInBytes, sizeof(uint8_t), inputFile);
                    if (!bytesRead) {
                        printf("Reached end of input file\n");
                        break;
                    }
                    fgcCTx.decBufY = pdecPelFrm;
                    if (fgcCTx.bitDepth > 8) {
                        fgcCTx.decBufU =
                            (void *)((uint16_t *)pdecPelFrm +
                                     psFgsAppParams->frameWidth * psFgsAppParams->frameHeight);
                        fgcCTx.decBufV =
                            (void *)((uint16_t *)fgcCTx.decBufU +
                                     (psFgsAppParams->frameWidth >> width_shift) *
                                         (psFgsAppParams->frameHeight >> height_shift));
                    } else {
                        fgcCTx.decBufU =
                            (void *)((uint8_t *)pdecPelFrm +
                                     psFgsAppParams->frameWidth * psFgsAppParams->frameHeight);
                        fgcCTx.decBufV =
                            (void *)((uint8_t *)fgcCTx.decBufU +
                                     (psFgsAppParams->frameWidth >> width_shift) *
                                         (psFgsAppParams->frameHeight >> height_shift));
                    }
                    fgcCTx.strideY = psFgsAppParams->frameWidth;
                    fgcCTx.strideU = (psFgsAppParams->frameWidth >> width_shift);
                    fgcCTx.strideV = (psFgsAppParams->frameWidth >> width_shift);

                    /* Function call to Film Grain Synthesizer */
                    fgcCTx.errorCode = fgs_process(fgcCTx, psFgsHandle);
                    if (FGS_SUCCESS != fgcCTx.errorCode) {
                        printf(" \n Grain synthesis in not performed. Error code: 0x%x ",
                               fgcCTx.errorCode);
                    }
                    frameNum++;
#if ENABLE_VIDEO_WRITE
                    fwrite(pdecPelFrm, sizeInBytes, sizeof(uint8_t), outputFile);
#endif
                } /* End of interface between App and Lib */
            } else {
                printf("Invalid value specified for startFrameNum in configuration file: %s\n",
                       psFgsAppParams->initParamsCfgFile);
                fclose(inputFile);
                return FAILURE_RET;
            }
        }
    }
    /* Close configuration file */
    fclose(inputFile);
    fclose(outputFile);
    fgs_delete(psFgsHandle);
    if (NULL != psFgsAppParams) {
        free(pdecPelFrm);
        free(psFgsAppParams);
    }

    printf("Done executing Film Grain Synthesizer\n");
    return SUCCESS_RET;
}
