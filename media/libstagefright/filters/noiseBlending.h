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
 ***************************************************************************/


#ifndef NOISE_BLEND_H_
#define NOISE_BLEND_H_

/* Macro definitions */
#define FGS_MAX_NUM_COMP 3
#define FGS_MAX_NUM_INTENSITIES 256
#define FGS_MAX_NUM_MODEL_VALUES 6

#define MAX_ALLOWED_MODEL_VALUES_MINUS1 2
#define MIN_LOG2SCALE_VALUE 2
#define MAX_LOG2SCALE_VALUE 7
#define FILM_GRAIN_MODEL_ID_VALUE 0
#define BLENDING_MODE_VALUE 0
#define MAX_STANDARD_DEVIATION 255
#define MIN_CUT_OFF_FREQUENCY 2
#define MAX_CUT_OFF_FREQUENCY 14
#define DEFAULT_HORZ_CUT_OFF_FREQUENCY 8
#define MAX_ALLOWED_COMP_MODEL_PAIRS 10

#define SCALE_DOWN_422  181 /* in Q-format of 8 : 1/sqrt(2) */
#define Q_FORMAT_SCALING 8
#define GRAIN_SCALE 6

#define MIN_WIDTH 128
#define MAX_WIDTH 7680
#define MIN_HEIGHT 128
#define MAX_HEIGHT 4320

#define MIN_CHROMA_FORMAT_IDC 0
#define MAX_CHROMA_FORMAT_IDC 3
#define MIN_BIT_DEPTH 8
#define MAX_BIT_DEPTH 16
#define BIT_DEPTH_8 8
#define NUM_8x8_BLKS_16x16 4
#define BLK_8 8
#define BLK_8_shift 6   //2^6 is 64
#define BLK_16_shift 8
#define BLK_AREA_8x8 64
#define BLK_AREA_16x16 256
#define BLK_16 16
#define INTENSITY_INTERVAL_MATCH_FAIL -1
#define COLOUR_OFFSET_LUMA 0
#define COLOUR_OFFSET_CR 85
#define COLOUR_OFFSET_CB 170

#define NUM_CUT_OFF_FREQ 13
#define DATA_BASE_SIZE 64
#define BLOCK_IDX 2 //0 = blksize 8, 1 = blksize 16

/* Function Macro definitions */
#define CLIP3(min, max, x) (((x) > (max)) ? (max) :(((x) < (min))? (min):(x)))
#define MIN(x,y) (((x) > (y)) ? (y) : (x))
#define MAX(x,y) (((x) > (y)) ? (x) : (y))
#define MSB16(x) ((x&0xFFFF0000)>>16)
#define LSB16(x) (x&0x0000FFFF)
#define BIT0(x) (x&0x1)
#define POS_30 (1<<30)
#define POS_2 (1<<2)

/* Error Macro definition */
#define FAILURE_RET 1
#define SUCCESS_RET 0
/* Error start codes for various classes of errors */
#define FGS_FILE_IO_ERROR    0x0010
#define FGS_PARAM_ERROR      0x0020
#define __arch64__

namespace android {

/* film grain characteritics SEI */
typedef struct FilmGrainCharacteristicsStruct_t
{
    /* To be 0 : to perform film grain synthesis */
    uint8_t filmGrainCharacteristicsCancelFlag;
    /* To be 0 : frequency filtering model */
    uint8_t filmGrainModelId;
    /* To be 0 : Decoded samples and grain to be in same color space */
    uint8_t separateColourDescriptionPresentFlag;
    uint8_t filmGrainBitDepthLumaMinus8;
    uint8_t filmGrainBitDepthChromaMinus8;
    uint8_t filmGrainFullRangeFlag;
    uint8_t filmGrainColourPrimaries;
    uint8_t filmGrainTransferCharacteristics;
    uint8_t filmGrainMatrixCoefficients;
    /* To be 0 : additive blending */
    uint8_t blendingModeId;
    /* To be in range of 2-7 : scale factor used in film grain simulation*/
    uint8_t log2ScaleFactor;
    /* To be either 8 or 16 : blockSize used in film grain simulation*/
    uint8_t blockSize;
    /* To disable chroma components or not */
    uint8_t disableFGSforChroma;
    /* Control for component model for each component*/
    uint8_t compModelPresentFlag[FGS_MAX_NUM_COMP];
    /* Number of intensity intervals in each component */
    uint8_t numIntensityIntervalsMinus1[FGS_MAX_NUM_COMP];
    /* Number of model values in each component */
    uint8_t numModelValuesMinus1[FGS_MAX_NUM_COMP];
    /* Lower bound of intensity interval */
    uint8_t intensityIntervalLowerBound[FGS_MAX_NUM_COMP][FGS_MAX_NUM_INTENSITIES];
    /* Upper bound of intensity interval */
    uint8_t intensityIntervalUpperBound[FGS_MAX_NUM_COMP][FGS_MAX_NUM_INTENSITIES];
    /* Component model values for each intensity interval */
    uint32_t compModelValue[FGS_MAX_NUM_COMP][FGS_MAX_NUM_INTENSITIES][FGS_MAX_NUM_MODEL_VALUES];
    /* To be 0:  Persistence of the film grain characteristics */
    uint32_t filmGrainCharacteristicsRepetitionPeriod;
}FilmGrainCharacteristicsStruct;

typedef struct GrainCharacteristicApi_t
{
    /* decoder output samples */
    void *decBufY;
    /* decoder output samples */
    void *decBufU;
    /* decoder output samples */
    void *decBufV;
    /* width of the frame */
    uint32_t width;
    /* height of the frame */
    uint32_t height;
    /* 0 : monochrome; 1: 420; 2: 422; 3: 444 */
    uint8_t chromaFormat;
    /* Stride of input buffer Y */
    uint32_t strideY;
    /* Stride of input buffer U */
    uint32_t strideU;
    /* Stride of input buffer V */
    uint32_t strideV;
    /* 8,10,12,14 and 16 bits */
    uint8_t bitDepth;
    /* decoded frame picture order count */
    uint32_t poc;
    /* 0: non-IDR pics */
    uint32_t idrPicId;
    /* Return error from Film grain synthesizer */
    uint32_t errorCode;
    /* Film grain chacracteristics */
    FilmGrainCharacteristicsStruct fgcParameters;
}GrainCharacteristicApi;

typedef struct GrainSynthesisStruct_t
{
    int8_t dataBase[BLOCK_IDX][NUM_CUT_OFF_FREQ][NUM_CUT_OFF_FREQ][DATA_BASE_SIZE][DATA_BASE_SIZE];
    int16_t intensityInterval[FGS_MAX_NUM_COMP][FGS_MAX_NUM_INTENSITIES];

}GrainSynthesisStruct;

typedef struct fgsProcessArgs{
    uint8_t numComp;
    uint32_t* fgsOffsets[FGS_MAX_NUM_COMP];
    void*    decComp[FGS_MAX_NUM_COMP];
    uint32_t widthComp[FGS_MAX_NUM_COMP];
    uint32_t heightComp[FGS_MAX_NUM_COMP];
    uint32_t strideComp[FGS_MAX_NUM_COMP];
    FilmGrainCharacteristicsStruct fgcParams;
    GrainSynthesisStruct *grainSynt;
    uint8_t bitDepth;
}fgsProcessArgs;

typedef struct fgsHandle
{
    GrainSynthesisStruct grainSynt;
}fgsHandle;

/* Error codes for various errors in SMPTE-RDD5 standalone grain synthesizer */
typedef enum
{
    /* No error */
    FGS_SUCCESS                           = 0,
    /* Invalid input width */
    FGS_INVALID_WIDTH                     = FGS_FILE_IO_ERROR + 0x01,
    /* Invalid input height */
    FGS_INVALID_HEIGHT                    = FGS_FILE_IO_ERROR + 0x02,
    /* Invalid Chroma format idc */
    FGS_INVALID_CHROMA_FORMAT             = FGS_FILE_IO_ERROR + 0x03,
    /* Invalid bit depth */
    FGS_INVALID_BIT_DEPTH                 = FGS_FILE_IO_ERROR + 0x04,
    /* Invalid Film grain characteristic cancel flag */
    FGS_INVALID_FGC_CANCEL_FLAG           = FGS_PARAM_ERROR + 0x01,
    /* Invalid film grain model id */
    FGS_INVALID_GRAIN_MODEL_ID            = FGS_PARAM_ERROR + 0x02,
    /* Invalid separate color description present flag */
    FGS_INVALID_SEP_COL_DES_FLAG          = FGS_PARAM_ERROR + 0x03,
    /* Invalid blending mode */
    FGS_INVALID_BLEND_MODE                = FGS_PARAM_ERROR + 0x04,
    /* Invalid log_2_scale_factor value */
    FGS_INVALID_LOG2_SCALE_FACTOR         = FGS_PARAM_ERROR + 0x05,
    /* Invalid component model present flag */
    FGS_INVALID_COMP_MODEL_PRESENT_FLAG   = FGS_PARAM_ERROR + 0x06,
    /* Invalid number of model values */
    FGS_INVALID_NUM_MODEL_VALUES          = FGS_PARAM_ERROR + 0x07,
    /* Invalid bound values, overlapping boundaries */
    FGS_INVALID_INTENSITY_BOUNDARY_VALUES = FGS_PARAM_ERROR + 0x08,
    /* Invalid standard deviation */
    FGS_INVALID_STANDARD_DEVIATION        = FGS_PARAM_ERROR + 0x09,
    /* Invalid cut off frequencies */
    FGS_INVALID_CUT_OFF_FREQUENCIES       = FGS_PARAM_ERROR + 0x0A,
    /* Invalid number of cut off frequency pairs */
    FGS_INVALID_NUM_CUT_OFF_FREQ_PAIRS    = FGS_PARAM_ERROR + 0x0B,
    /* Invalid film grain characteristics repetition period */
    FGS_INVALID_FGC_REPETETION_PERIOD     = FGS_PARAM_ERROR + 0x0C,
    /* Invalid blockSize value */
    FGS_INVALID_BLOCK_SIZE                = FGS_PARAM_ERROR + 0x0D,
    /* Failure error code */
    FGS_FAIL                               = 0xFF
}FGS_ERROR_T;

void* fgs_create();
void  fgs_delete(void *psFgsHandle);
uint32_t fgs_process(GrainCharacteristicApi fgsParamStruct,void *psFgsHandle);
uint32_t fgs_validate_input_params(GrainCharacteristicApi fgsParamStruct);

} // namespace android

#endif  // NOISE_BLEND_H_
