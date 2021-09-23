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
 * \file grainBlendingIntrinsics.cpp
 *
 * \brief
 *    Contains functions in intrinsics used for grain blending
 *
 * \date
 *    14/09/2021
 *
 * \author  NS
 **************************************************************************
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "grainBlending.h"

#if defined(__aarch64__)
#include <arm_neon.h>

namespace android {

void blend_stripe_av8(uint16_t *decSampleHbdOffsetY, int8_t *grainStripe, uint32_t widthComp,
                      uint32_t grainStripeWidth, uint32_t blockHeight, uint8_t bitDepth) {
  uint32_t k, l;
  uint16_t maxRange;
  maxRange = (1 << bitDepth) - 1;

  int16x8_t v_16x8_shiftleft = vdupq_n_s16(bitDepth - BIT_DEPTH_8);
  uint16x8_t v_u16x8_maxRange = vdupq_n_u16(maxRange);
  if ((widthComp & 0x7) == 0) {
    for (l = 0; l < blockHeight; l++) {
      for (k = 0; k < widthComp; k += BLK_8) {
        uint16x8_t v_u16x8_decodeSample = vld1q_u16(decSampleHbdOffsetY);
        int8x8_t v_8x8_grainStripe = vld1_s8(grainStripe);
        int16x8_t v_16x8_grainStripe = vmovl_s8(v_8x8_grainStripe);
        v_16x8_grainStripe = vshlq_s16(v_16x8_grainStripe, v_16x8_shiftleft);
        uint16x8_t v_u16x8_output = vsqaddq_u16(v_u16x8_decodeSample, v_16x8_grainStripe);
        v_u16x8_output = vminq_u16(v_u16x8_output, v_u16x8_maxRange);
        vst1q_u16(decSampleHbdOffsetY, v_u16x8_output);
        decSampleHbdOffsetY += BLK_8;
        grainStripe += BLK_8;
      }
      grainStripe += grainStripeWidth - widthComp;
    }
  } else {
    int32_t grainSample;
    for (l = 0; l < blockHeight; l++) {
      for (k = 0; k < widthComp - BLK_8; k += BLK_8) {
        uint16x8_t v_u16x8_decodeSample = vld1q_u16(decSampleHbdOffsetY);
        int8x8_t v_8x8_grainStripe = vld1_s8(grainStripe);
        int16x8_t v_16x8_grainStripe = vmovl_s8(v_8x8_grainStripe);
        v_16x8_grainStripe = vshlq_s16(v_16x8_grainStripe, v_16x8_shiftleft);
        uint16x8_t v_u16x8_output = vsqaddq_u16(v_u16x8_decodeSample, v_16x8_grainStripe);
        v_u16x8_output = vminq_u16(v_u16x8_output, v_u16x8_maxRange);
        vst1q_u16(decSampleHbdOffsetY, v_u16x8_output);
        decSampleHbdOffsetY += BLK_8;
        grainStripe += BLK_8;
      }
      for (; k < widthComp; k++) {
        grainSample = *grainStripe;
        grainSample <<= (bitDepth - BIT_DEPTH_8);
        grainSample = CLIP3(0, maxRange, grainSample + *decSampleHbdOffsetY);
        *decSampleHbdOffsetY = (uint16_t)grainSample;
        decSampleHbdOffsetY++;
        grainStripe++;
      }
      grainStripe += grainStripeWidth - widthComp;
    }
  }
  return;
}

void blend_stripe_av8(uint8_t *decSampleOffsetY, int8_t *grainStripe, uint32_t widthComp,
                      uint32_t grainStripeWidth, uint32_t blockHeight, uint8_t bitDepth) {
  uint32_t k, l;

  if ((widthComp & 0xF) == 0) {
    for (l = 0; l < blockHeight; l++) {
      for (k = 0; k < widthComp; k += BLK_16) {
        uint8x16_t v_u8x16_decodeSample = vld1q_u8(decSampleOffsetY);
        int8x16_t v_8x16_grainStripe = vld1q_s8(grainStripe);
        uint8x16_t v_u8x16_output = vsqaddq_u8(v_u8x16_decodeSample, v_8x16_grainStripe);
        vst1q_u8(decSampleOffsetY, v_u8x16_output);
        decSampleOffsetY += BLK_16;
        grainStripe += BLK_16;
      }
      grainStripe += grainStripeWidth - widthComp;
    }
  } else {
    int32_t grainSample;
    uint8_t decodeSample;
    uint16_t maxRange;
    maxRange = (1 << bitDepth) - 1;
    for (l = 0; l < blockHeight; l++) {
      for (k = 0; k < widthComp - BLK_16; k += BLK_16) {
        uint8x16_t v_u8x16_decodeSample = vld1q_u8(decSampleOffsetY);
        int8x16_t v_8x16_grainStripe = vld1q_s8(grainStripe);
        uint8x16_t v_u8x16_output = vsqaddq_u8(v_u8x16_decodeSample, v_8x16_grainStripe);
        vst1q_u8(decSampleOffsetY, v_u8x16_output);
        decSampleOffsetY += BLK_16;
        grainStripe += BLK_16;
      }
      for (; k < widthComp; k++) {
        decodeSample = *decSampleOffsetY;
        grainSample = *grainStripe;
        grainSample = CLIP3(0, maxRange, (grainSample + decodeSample));
        *decSampleOffsetY = (uint8_t)grainSample;
        decSampleOffsetY++;
        grainStripe++;
      }
      grainStripe += grainStripeWidth - widthComp;
    }
  }
  return;
}

uint32_t block_avg_8x8_av8(uint16_t *decSampleBlk8, uint32_t widthComp, uint8_t bitDepth,
                           int16_t blkSz, int16_t blkShift) {
  uint32_t blockAvg = 0;
  uint8_t k;

  uint16x8_t u16x8_blockAvg = vdupq_n_u16(0);  // vmovq_n_u16
  for (k = 0; k < blkSz; k++) {
    uint16x8_t u16x8_decSample = vld1q_u16(decSampleBlk8);
    decSampleBlk8 += widthComp;
    u16x8_blockAvg = vaddq_u16(u16x8_blockAvg, u16x8_decSample);
  }
  blockAvg = vaddvq_u16(u16x8_blockAvg);
  blockAvg = blockAvg >> (blkShift + (bitDepth - BIT_DEPTH_8));

  return blockAvg;
}

uint32_t block_avg_16x16_av8(uint16_t *decSampleBlk8, uint32_t widthComp, uint8_t bitDepth,
                             int16_t blkSz, int16_t blkShift) {
  uint32_t blockAvg = 0;
  uint8_t k;

  uint16x8_t u16x8_blockAvg1 = vdupq_n_u16(0);  // vmovq_n_u16
  uint16x8_t u16x8_blockAvg2 = vdupq_n_u16(0);
  for (k = 0; k < blkSz; k++) {
    uint16x8_t u16x8_decSample1 = vld1q_u16(decSampleBlk8);
    decSampleBlk8 += BLK_8;
    uint16x8_t u16x8_decSample2 = vld1q_u16(decSampleBlk8);
    decSampleBlk8 += widthComp - BLK_8;
    u16x8_blockAvg1 = vaddq_u16(u16x8_blockAvg1, u16x8_decSample1);
    u16x8_blockAvg2 = vaddq_u16(u16x8_blockAvg2, u16x8_decSample2);
  }
  uint32x4_t u32x4_blockAvg1 = vpaddlq_u16(u16x8_blockAvg1);
  uint32x4_t u32x4_blockAvg2 = vpaddlq_u16(u16x8_blockAvg2);

  blockAvg = vaddvq_u32(u32x4_blockAvg1) + vaddvq_u32(u32x4_blockAvg2);
  blockAvg = blockAvg >> (blkShift + (bitDepth - BIT_DEPTH_8));

  return blockAvg;
}

uint32_t block_avg_8x8_av8(uint8_t *decSampleBlk8, uint32_t widthComp, uint8_t bitDepth,
                           int16_t blkSz, int16_t blkShift) {
  uint32_t blockAvg = 0;
  uint8_t k;

  uint16x8_t u16x8_blockAvg = vdupq_n_u16(0);  // vmovq_n_u16
  for (k = 0; k < blkSz; k += 2) {
    uint8x8_t u8x8_decSample1 = vld1_u8(decSampleBlk8);
    decSampleBlk8 += widthComp;
    uint8x8_t u8x8_decSample2 = vld1_u8(decSampleBlk8);
    decSampleBlk8 += widthComp;
    uint8x16_t u8x16_decSampl = vcombine_u8(u8x8_decSample1, u8x8_decSample2);
    u16x8_blockAvg = vpadalq_u8(u16x8_blockAvg, u8x16_decSampl);
  }
  blockAvg = vaddvq_u16(u16x8_blockAvg);
  blockAvg = blockAvg >> (blkShift + (bitDepth - BIT_DEPTH_8));

  return blockAvg;
}

uint32_t block_avg_16x16_av8(uint8_t *decSampleBlk8, uint32_t widthComp, uint8_t bitDepth,
                             int16_t blkSz, int16_t blkShift) {
  uint32_t blockAvg = 0;
  uint8_t k;

  uint16x8_t u16x8_blockAvg = vdupq_n_u16(0);
  for (k = 0; k < blkSz; k++) {
    uint8x16_t u8x16_decSampl = vld1q_u8(decSampleBlk8);
    decSampleBlk8 += widthComp;
    u16x8_blockAvg = vpadalq_u8(u16x8_blockAvg, u8x16_decSampl);
  }
  blockAvg = vaddvq_u16(u16x8_blockAvg);
  blockAvg = blockAvg >> (blkShift + (bitDepth - BIT_DEPTH_8));

  return blockAvg;
}

void simulate_grain_blk16x16_av8(int8_t *grainStripe, uint32_t grainStripeOffsetBlk8,
                                 GrainSynthesisStruct *grain_synt, uint32_t width,
                                 uint8_t log2ScaleFactor, int16_t scaleFactor, uint32_t kOffset,
                                 uint32_t lOffset, uint8_t h, uint8_t v, uint32_t blkSz) {
  uint32_t l;
  int8_t *database_h_v = &grain_synt->dataBase[1][h][v][lOffset][kOffset];
  grainStripe += grainStripeOffsetBlk8;

  int16x8_t v_16x8_ShiftFactor = vdupq_n_s16(-(log2ScaleFactor + GRAIN_SCALE));
  for (l = 0; l < blkSz; l++) {
    int8x16_t v_8x16_database = vld1q_s8(database_h_v);
    database_h_v += DATA_BASE_SIZE;
    int8x8_t v_8x8_database1 = vget_high_s8(v_8x16_database);
    int8x8_t v_8x8_database2 = vget_low_s8(v_8x16_database);

    int16x8_t v_16x8_database1 = vmovl_s8(v_8x8_database1);
    int16x8_t v_16x8_database2 = vmovl_s8(v_8x8_database2);

    int16x8_t v_16x8_grainStripe1 = vmulq_n_s16(v_16x8_database1, scaleFactor);

    v_16x8_grainStripe1 = vshlq_s16(v_16x8_grainStripe1, v_16x8_ShiftFactor);
    int16x8_t v_16x8_grainStripe2 = vmulq_n_s16(v_16x8_database2, scaleFactor);

    v_16x8_grainStripe2 = vshlq_s16(v_16x8_grainStripe2, v_16x8_ShiftFactor);

    int8x8_t v_8x8_grainStripe1 = vmovn_s16(v_16x8_grainStripe1);
    int8x8_t v_8x8_grainStripe2 = vmovn_s16(v_16x8_grainStripe2);
    int8x16_t v_8x16_grainStripe = vcombine_s8(v_8x8_grainStripe2, v_8x8_grainStripe1);
    vst1q_s8(grainStripe, v_8x16_grainStripe);
    grainStripe += width;
  }

  return;
}

void simulate_grain_blk8x8_av8(int8_t *grainStripe, uint32_t grainStripeOffsetBlk8,
                               GrainSynthesisStruct *grain_synt, uint32_t width,
                               uint8_t log2ScaleFactor, int16_t scaleFactor, uint32_t kOffset,
                               uint32_t lOffset, uint8_t h, uint8_t v, uint32_t blkSz) {
  uint32_t l;
  int8_t *database_h_v = &grain_synt->dataBase[0][h][v][lOffset][kOffset];
  grainStripe += grainStripeOffsetBlk8;

  int16x8_t v_16x8_ShiftFactor = vdupq_n_s16(-(log2ScaleFactor + GRAIN_SCALE));
  for (l = 0; l < blkSz; l++) {
    int8x8_t v_8x8_database = vld1_s8(database_h_v);
    database_h_v += DATA_BASE_SIZE;

    int16x8_t v_16x8_database = vmovl_s8(v_8x8_database);
    int16x8_t v_16x8_grainStripe = vmulq_n_s16(v_16x8_database, scaleFactor);
    v_16x8_grainStripe = vshlq_s16(v_16x8_grainStripe, v_16x8_ShiftFactor);

    int8x8_t v_8x8_grainStripe = vmovn_s16(v_16x8_grainStripe);
    vst1_s8(grainStripe, v_8x8_grainStripe);
    grainStripe += width;
  }

  return;
}

}  // namespace android

#elif defined(__x86_64__)

#include <emmintrin.h>
#include <immintrin.h>

namespace android {

void blend_stripe_avx(uint16_t *decSampleHbdOffsetY, int8_t *grainStripe, uint32_t widthComp,
                      uint32_t grainStripeWidth, uint32_t blockHeight, uint8_t bitDepth) {
  uint32_t k, l;
  uint16_t maxRange;
  maxRange = (1 << bitDepth) - 1;

  __m128i __m128i_maxrange = _mm_set1_epi16(maxRange);
  __m128i __m128i_minZero = _mm_set1_epi16(0);
  if ((widthComp & 0x7) == 0) {
    for (l = 0; l < blockHeight; l++) {
      for (k = 0; k < widthComp; k += BLK_8) {
        __m128i __m128i_decData = _mm_loadu_si128((__m128i *)decSampleHbdOffsetY);
        __m128i __m128i_grainSt = _mm_loadu_si128((__m128i *)grainStripe);
        __m128i_grainSt = _mm_cvtepi8_epi16(__m128i_grainSt);
        __m128i_grainSt = _mm_slli_epi16(__m128i_grainSt, (bitDepth - BIT_DEPTH_8));
        __m128i __m128i_sum = _mm_add_epi16(__m128i_decData, __m128i_grainSt);
        __m128i_sum = _mm_min_epi16(__m128i_sum, __m128i_maxrange);
        __m128i_sum = _mm_max_epi16(__m128i_sum, __m128i_minZero);
        _mm_store_si128((__m128i *)decSampleHbdOffsetY, __m128i_sum);
        decSampleHbdOffsetY += BLK_8;
        grainStripe += BLK_8;
      }
      grainStripe += grainStripeWidth - widthComp;
    }
  } else {
    int32_t grainSample;
    uint16_t decodeSample;
    for (l = 0; l < blockHeight; l++) {
      for (k = 0; k < widthComp - BLK_8; k += BLK_8) {
        __m128i __m128i_decData = _mm_loadu_si128((__m128i *)decSampleHbdOffsetY);
        __m128i __m128i_grainSt = _mm_loadu_si128((__m128i *)grainStripe);
        __m128i_grainSt = _mm_cvtepi8_epi16(__m128i_grainSt);
        __m128i_grainSt = _mm_slli_epi16(__m128i_grainSt, (bitDepth - BIT_DEPTH_8));
        __m128i __m128i_sum = _mm_add_epi16(__m128i_decData, __m128i_grainSt);
        __m128i_sum = _mm_min_epi16(__m128i_sum, __m128i_maxrange);
        __m128i_sum = _mm_max_epi16(__m128i_sum, __m128i_minZero);
        _mm_storeu_si128((__m128i *)decSampleHbdOffsetY, __m128i_sum);
        decSampleHbdOffsetY += BLK_8;
        grainStripe += BLK_8;
      }
      for (; k < widthComp; k++) {
        decodeSample = *decSampleHbdOffsetY;
        grainSample = *grainStripe;
        grainSample <<= (bitDepth - BIT_DEPTH_8);
        grainSample = CLIP3(0, maxRange, (grainSample + decodeSample));
        *decSampleHbdOffsetY = (uint16_t)grainSample;
        decSampleHbdOffsetY++;
        grainStripe++;
      }
      grainStripe += grainStripeWidth - widthComp;
    }
  }

  return;
}

void blend_stripe_avx(uint8_t *decSampleOffsetY, int8_t *grainStripe, uint32_t widthComp,
                      uint32_t grainStripeWidth, uint32_t blockHeight, uint8_t bitDepth) {
  uint32_t k, l;

  if ((widthComp & 0xF) == 0) {
    for (l = 0; l < blockHeight; l++) {
      for (k = 0; k < widthComp; k += BLK_16) {
        __m128i __m128i_decData = _mm_loadu_si128((__m128i *)decSampleOffsetY);
        __m128i __m128i_grainSt = _mm_loadu_si128((__m128i *)grainStripe);

        __m128i __m128i_decData1 = _mm_cvtepu8_epi16(__m128i_decData);
        __m128i __m128i_decData2 =
            _mm_cvtepu8_epi16(_mm_loadu_si128((__m128i *)(decSampleOffsetY + BLK_8)));

        __m128i __m128i_grainSt1 = _mm_cvtepi8_epi16(__m128i_grainSt);
        __m128i __m128i_grainSt2 =
            _mm_cvtepi8_epi16(_mm_loadu_si128((__m128i *)(grainStripe + BLK_8)));

        __m128i __m128i_sum1 = _mm_add_epi16(__m128i_decData1, __m128i_grainSt1);
        __m128i __m128i_sum2 = _mm_add_epi16(__m128i_decData2, __m128i_grainSt2);
        __m128i __m128i_sum = _mm_packus_epi16(__m128i_sum1, __m128i_sum2);
        _mm_storeu_si128((__m128i *)decSampleOffsetY, __m128i_sum);
        decSampleOffsetY += BLK_16;
        grainStripe += BLK_16;
      }
      grainStripe += grainStripeWidth - widthComp;
    }
  } else {
    int32_t grainSample;
    uint8_t decodeSample;
    uint16_t maxRange;
    maxRange = (1 << bitDepth) - 1;
    for (l = 0; l < blockHeight; l++) {
      for (k = 0; k < widthComp - BLK_16; k += BLK_16) {
        __m128i __m128i_decData = _mm_loadu_si128((__m128i *)decSampleOffsetY);
        __m128i __m128i_grainSt = _mm_loadu_si128((__m128i *)grainStripe);

        __m128i __m128i_decData1 = _mm_cvtepu8_epi16(__m128i_decData);
        __m128i __m128i_decData2 =
            _mm_cvtepu8_epi16(_mm_loadu_si128((__m128i *)(decSampleOffsetY + BLK_8)));

        __m128i __m128i_grainSt1 = _mm_cvtepi8_epi16(__m128i_grainSt);
        __m128i __m128i_grainSt2 =
            _mm_cvtepi8_epi16(_mm_loadu_si128((__m128i *)(grainStripe + BLK_8)));

        __m128i __m128i_sum1 = _mm_add_epi16(__m128i_decData1, __m128i_grainSt1);
        __m128i __m128i_sum2 = _mm_add_epi16(__m128i_decData2, __m128i_grainSt2);
        __m128i __m128i_sum = _mm_packus_epi16(__m128i_sum1, __m128i_sum2);
        _mm_storeu_si128((__m128i *)decSampleOffsetY, __m128i_sum);
        decSampleOffsetY += BLK_16;
        grainStripe += BLK_16;
      }
      for (; k < widthComp; k++) {
        decodeSample = *decSampleOffsetY;
        grainSample = *grainStripe;
        grainSample = CLIP3(0, maxRange, (grainSample + decodeSample));
        *decSampleOffsetY = (uint8_t)grainSample;
        decSampleOffsetY++;
        grainStripe++;
      }
      grainStripe += grainStripeWidth - widthComp;
    }
  }

  return;
}

uint32_t block_avg_8x8_avx(uint16_t *decSampleBlk8, uint32_t widthComp, uint8_t bitDepth,
                           int16_t blkSz, int16_t blkShift) {
  uint32_t blockAvg = 0;
  uint8_t k;

  __m128i __m128i_sumRegister = _mm_loadu_si128((__m128i *)decSampleBlk8);
  decSampleBlk8 += widthComp;

  for (k = 1; k < blkSz; k++) {
    __m128i __m128i_decData = _mm_loadu_si128((__m128i *)decSampleBlk8);
    decSampleBlk8 += widthComp;
    __m128i_sumRegister = _mm_add_epi16(__m128i_sumRegister, __m128i_decData);
  }
  __m128i __m128i_zeros = _mm_set1_epi16(0);
  __m128i_sumRegister = _mm_hadds_epi16(__m128i_sumRegister, __m128i_zeros);
  __m128i_sumRegister = _mm_hadds_epi16(__m128i_sumRegister, __m128i_zeros);

  blockAvg = ((uint32_t)_mm_extract_epi16(__m128i_sumRegister, 0)) +
             ((uint32_t)_mm_extract_epi16(__m128i_sumRegister, 1));
  blockAvg = blockAvg >> (blkShift + (bitDepth - BIT_DEPTH_8));

  return blockAvg;
}

uint32_t block_avg_16x16_avx(uint16_t *decSampleBlk8, uint32_t widthComp, uint8_t bitDepth,
                             int16_t blkSz, int16_t blkShift) {
  uint32_t blockAvg = 0;
  uint8_t k;

  __m128i __m128i_sumRegister1 = _mm_loadu_si128((__m128i *)decSampleBlk8);
  __m128i __m128i_sumRegister2 = _mm_loadu_si128((__m128i *)(decSampleBlk8 + BLK_8));

  decSampleBlk8 += widthComp;

  for (k = 1; k < blkSz; k++) {
    __m128i __m128i_decData1 = _mm_loadu_si128((__m128i *)decSampleBlk8);
    __m128i __m128i_decData2 = _mm_loadu_si128((__m128i *)(decSampleBlk8 + BLK_8));
    decSampleBlk8 += widthComp;
    __m128i_sumRegister1 = _mm_add_epi16(__m128i_sumRegister1, __m128i_decData1);
    __m128i_sumRegister2 = _mm_add_epi16(__m128i_sumRegister2, __m128i_decData2);
  }
  __m128i __m128i_zeros = _mm_set1_epi16(0);
  __m128i_sumRegister1 = _mm_hadds_epi16(__m128i_sumRegister1, __m128i_zeros);
  __m128i_sumRegister2 = _mm_hadds_epi16(__m128i_sumRegister2, __m128i_zeros);
  __m128i_sumRegister1 = _mm_cvtepi16_epi32(__m128i_sumRegister1);
  __m128i_sumRegister2 = _mm_cvtepi16_epi32(__m128i_sumRegister2);
  __m128i __m128i_sumRegister = _mm_hadd_epi32(__m128i_sumRegister1, __m128i_sumRegister2);
  __m128i_zeros = _mm_set1_epi32(0);
  __m128i_sumRegister = _mm_hadd_epi32(__m128i_sumRegister, __m128i_zeros);
  __m128i_sumRegister = _mm_hadd_epi32(__m128i_sumRegister, __m128i_zeros);

  blockAvg = (uint32_t)_mm_extract_epi32(__m128i_sumRegister, 0);
  blockAvg = blockAvg >> (blkShift + (bitDepth - BIT_DEPTH_8));

  return blockAvg;
}

uint32_t block_avg_8x8_avx(uint8_t *decSampleBlk8, uint32_t widthComp, uint8_t bitDepth,
                           int16_t blkSz, int16_t blkShift) {
  uint32_t blockAvg = 0;
  uint8_t k;
  __m128i __m128i_decData = _mm_loadu_si128((__m128i *)decSampleBlk8);
  decSampleBlk8 += widthComp;
  __m128i __m128i_sumRegister = _mm_cvtepu8_epi16(__m128i_decData);
  for (k = 1; k < blkSz; k++) {
    __m128i_decData = _mm_loadu_si128((__m128i *)decSampleBlk8);
    decSampleBlk8 += widthComp;
    __m128i_decData = _mm_cvtepu8_epi16(__m128i_decData);
    __m128i_sumRegister = _mm_add_epi16(__m128i_sumRegister, __m128i_decData);
  }
  __m128i __m128i_zeros = _mm_set1_epi16(0);
  __m128i_sumRegister = _mm_hadds_epi16(__m128i_sumRegister, __m128i_zeros);
  __m128i_sumRegister = _mm_hadds_epi16(__m128i_sumRegister, __m128i_zeros);
  __m128i_sumRegister = _mm_hadds_epi16(__m128i_sumRegister, __m128i_zeros);

  blockAvg = ((uint32_t)_mm_extract_epi16(__m128i_sumRegister, 0));
  blockAvg = blockAvg >> (blkShift + (bitDepth - BIT_DEPTH_8));

  return blockAvg;
}

uint32_t block_avg_16x16_avx(uint8_t *decSampleBlk8, uint32_t widthComp, uint8_t bitDepth,
                             int16_t blkSz, int16_t blkShift) {
  uint32_t blockAvg = 0;
  uint8_t k;

  __m128i __m128i_decData1 = _mm_cvtepu8_epi16(_mm_loadu_si128((__m128i *)decSampleBlk8));
  __m128i __m128i_decData2 = _mm_cvtepu8_epi16(_mm_loadu_si128((__m128i *)(decSampleBlk8 + BLK_8)));
  __m128i __m128i_sumRegister = _mm_add_epi16(__m128i_decData1, __m128i_decData2);
  decSampleBlk8 += widthComp;

  for (k = 1; k < blkSz; k++) {
    __m128i_decData1 = _mm_cvtepu8_epi16(_mm_loadu_si128((__m128i *)decSampleBlk8));
    __m128i_decData2 = _mm_cvtepu8_epi16(_mm_loadu_si128((__m128i *)(decSampleBlk8 + BLK_8)));
    __m128i_sumRegister = _mm_add_epi16(__m128i_sumRegister, __m128i_decData1);
    __m128i_sumRegister = _mm_add_epi16(__m128i_sumRegister, __m128i_decData2);
    decSampleBlk8 += widthComp;
  }
  __m128i __m128i_zeros = _mm_set1_epi16(0);
  __m128i_sumRegister = _mm_hadds_epi16(__m128i_sumRegister, __m128i_zeros);
  __m128i_sumRegister = _mm_hadds_epi16(__m128i_sumRegister, __m128i_zeros);

  blockAvg = ((uint32_t)_mm_extract_epi16(__m128i_sumRegister, 0)) +
             ((uint32_t)_mm_extract_epi16(__m128i_sumRegister, 1));
  blockAvg = blockAvg >> (blkShift + (bitDepth - BIT_DEPTH_8));

  return blockAvg;
}

void simulate_grain_blk16x16_avx(int8_t *grainStripe, uint32_t grainStripeOffsetBlk8,
                                 GrainSynthesisStruct *grain_synt, uint32_t width,
                                 uint8_t log2ScaleFactor, int16_t scaleFactor, uint32_t kOffset,
                                 uint32_t lOffset, uint8_t h, uint8_t v, uint32_t blkSz) {
  uint32_t l;
  int8_t *database_h_v = &grain_synt->dataBase[1][h][v][lOffset][kOffset];
  grainStripe += grainStripeOffsetBlk8;

  __m128i __m128i_scaleFactor = _mm_set1_epi16(scaleFactor);
  int16_t shiftFactor = log2ScaleFactor + GRAIN_SCALE;

  for (l = 0; l < blkSz; l++) {
    __m128i __m128i_database_h_v = _mm_loadu_si128((__m128i *)database_h_v);
    __m128i __m128i_database_h_v1 = _mm_cvtepi8_epi16(__m128i_database_h_v);
    __m128i_database_h_v = _mm_loadu_si128((__m128i *)(database_h_v + BLK_8));
    database_h_v += DATA_BASE_SIZE;
    __m128i __m128i_database_h_v2 = _mm_cvtepi8_epi16(__m128i_database_h_v);

    __m128i __m128i_grainStripe1 = _mm_mullo_epi16(__m128i_database_h_v1, __m128i_scaleFactor);
    __m128i_grainStripe1 = _mm_srai_epi16(__m128i_grainStripe1, shiftFactor);
    __m128i __m128i_grainStripe2 = _mm_mullo_epi16(__m128i_database_h_v2, __m128i_scaleFactor);
    __m128i_grainStripe2 = _mm_srai_epi16(__m128i_grainStripe2, shiftFactor);

    __m128i __m128i_grainStripe = _mm_packs_epi16(__m128i_grainStripe1, __m128i_grainStripe2);

    _mm_storeu_si128((__m128i *)grainStripe, __m128i_grainStripe);
    grainStripe += width;
  }

  return;
}

void simulate_grain_blk8x8_avx(int8_t *grainStripe, uint32_t grainStripeOffsetBlk8,
                               GrainSynthesisStruct *grain_synt, uint32_t width,
                               uint8_t log2ScaleFactor, int16_t scaleFactor, uint32_t kOffset,
                               uint32_t lOffset, uint8_t h, uint8_t v, uint32_t blkSz) {
  uint32_t l;
  int8_t *database_h_v = &grain_synt->dataBase[0][h][v][lOffset][kOffset];
  grainStripe += grainStripeOffsetBlk8;

  __m128i __m128i_scaleFactor = _mm_set1_epi16(scaleFactor);
  __m128i __m128i_zerovals = _mm_set1_epi16(0);
  int16_t shiftFactor = log2ScaleFactor + GRAIN_SCALE;
  for (l = 0; l < blkSz; l += 2) {
    __m128i __m128i_database_h_v1 = _mm_loadu_si128((__m128i *)database_h_v);
    database_h_v += DATA_BASE_SIZE;
    __m128i_database_h_v1 = _mm_cvtepi8_epi16(__m128i_database_h_v1);

    __m128i __m128i_grainStripe1 = _mm_mullo_epi16(__m128i_database_h_v1, __m128i_scaleFactor);
    __m128i_grainStripe1 = _mm_srai_epi16(__m128i_grainStripe1, shiftFactor);

    __m128i __m128i_database_h_v2 = _mm_loadu_si128((__m128i *)database_h_v);
    database_h_v += DATA_BASE_SIZE;
    __m128i_database_h_v2 = _mm_cvtepi8_epi16(__m128i_database_h_v2);

    __m128i __m128i_grainStripe2 = _mm_mullo_epi16(__m128i_database_h_v2, __m128i_scaleFactor);
    __m128i_grainStripe2 = _mm_srai_epi16(__m128i_grainStripe2, shiftFactor);
    __m128i __m128i_grainStripe = _mm_packs_epi16(__m128i_grainStripe1, __m128i_zerovals);

    _mm_storel_epi64((__m128i *)grainStripe, __m128i_grainStripe);
    grainStripe += width;
    __m128i_grainStripe = _mm_packs_epi16(__m128i_grainStripe2, __m128i_zerovals);
    _mm_storel_epi64((__m128i *)grainStripe, __m128i_grainStripe);
    grainStripe += width;
  }

  return;
}

}  // namespace android
#endif
