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
/* Includes                                                                             */
/*                                                                                      */
/****************************************************************************************/
#include "LVREV_Private.h"
#include "VectorArithmetic.h"

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVREV_ClearAudioBuffers                                     */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  This function is used to clear the internal audio buffers of the module.            */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  hInstance               Instance handle                                             */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVREV_SUCCESS          Initialisation succeeded                                     */
/*  LVREV_NULLADDRESS      Instance is NULL                                             */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1. This function must not be interrupted by the LVM_Process function                */
/*                                                                                      */
/****************************************************************************************/
LVREV_ReturnStatus_en LVREV_ClearAudioBuffers(LVREV_Handle_t hInstance) {
    LVREV_Instance_st* pLVREV_Private = (LVREV_Instance_st*)hInstance;

    /*
     * Check for error conditions
     */
    /* Check for NULL pointers */
    if (hInstance == LVM_NULL) {
        return LVREV_NULLADDRESS;
    }

    /*
     * Clear all filter tap data, delay-lines and other signal related data
     */

#ifdef BIQUAD_OPT
    pLVREV_Private->pRevHPFBiquad->clear();
    pLVREV_Private->pRevLPFBiquad->clear();
#else
    LoadConst_Float(0, (LVM_FLOAT*)&pLVREV_Private->pFastData->HPTaps, 2);
    LoadConst_Float(0, (LVM_FLOAT*)&pLVREV_Private->pFastData->LPTaps, 2);
#endif
    if ((LVM_UINT16)pLVREV_Private->InstanceParams.NumDelays == LVREV_DELAYLINES_4) {
#ifdef BIQUAD_OPT
        for (int i = 0; i < LVREV_DELAYLINES_4; i++) {
            pLVREV_Private->revLPFBiquad[i]->clear();
        }
#else
        LoadConst_Float(0, (LVM_FLOAT*)&pLVREV_Private->pFastData->RevLPTaps[3], 2);
        LoadConst_Float(0, (LVM_FLOAT*)&pLVREV_Private->pFastData->RevLPTaps[2], 2);
        LoadConst_Float(0, (LVM_FLOAT*)&pLVREV_Private->pFastData->RevLPTaps[1], 2);
        LoadConst_Float(0, (LVM_FLOAT*)&pLVREV_Private->pFastData->RevLPTaps[0], 2);
#endif

        LoadConst_Float(0, pLVREV_Private->pDelay_T[3], LVREV_MAX_T3_DELAY);
        LoadConst_Float(0, pLVREV_Private->pDelay_T[2], LVREV_MAX_T2_DELAY);
        LoadConst_Float(0, pLVREV_Private->pDelay_T[1], LVREV_MAX_T1_DELAY);
        LoadConst_Float(0, pLVREV_Private->pDelay_T[0], LVREV_MAX_T0_DELAY);
    }

    if ((LVM_UINT16)pLVREV_Private->InstanceParams.NumDelays >= LVREV_DELAYLINES_2) {
#ifdef BIQUAD_OPT
        for (int i = 0; i < LVREV_DELAYLINES_2; i++) {
            pLVREV_Private->revLPFBiquad[i]->clear();
        }
#else
        LoadConst_Float(0, (LVM_FLOAT*)&pLVREV_Private->pFastData->RevLPTaps[1], 2);
        LoadConst_Float(0, (LVM_FLOAT*)&pLVREV_Private->pFastData->RevLPTaps[0], 2);
#endif

        LoadConst_Float(0, pLVREV_Private->pDelay_T[1], LVREV_MAX_T1_DELAY);
        LoadConst_Float(0, pLVREV_Private->pDelay_T[0], LVREV_MAX_T0_DELAY);
    }

    if ((LVM_UINT16)pLVREV_Private->InstanceParams.NumDelays >= LVREV_DELAYLINES_1) {
#ifdef BIQUAD_OPT
        pLVREV_Private->revLPFBiquad[0]->clear();
#else
        LoadConst_Float(0, (LVM_FLOAT*)&pLVREV_Private->pFastData->RevLPTaps[0], 2);
#endif
        LoadConst_Float(0, pLVREV_Private->pDelay_T[0], LVREV_MAX_T0_DELAY);
    }
    return LVREV_SUCCESS;
}

/* End of file */
