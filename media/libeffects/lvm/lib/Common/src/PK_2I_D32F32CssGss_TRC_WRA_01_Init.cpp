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

#include "BIQUAD.h"
#include "PK_2I_D32F32CssGss_TRC_WRA_01_Private.h"
void PK_2I_D32F32CssGss_TRC_WRA_01_Init(Biquad_FLOAT_Instance_t *pInstance,
                                        Biquad_2I_Order2_FLOAT_Taps_t *pTaps,
                                        PK_FLOAT_Coefs_t *pCoef) {
    PFilter_State_Float pBiquadState = (PFilter_State_Float)pInstance;
    pBiquadState->pDelays = (LVM_FLOAT *)pTaps;

    pBiquadState->coefs[0] = pCoef->A0;

    pBiquadState->coefs[1] = pCoef->B2;

    pBiquadState->coefs[2] = pCoef->B1;

    pBiquadState->coefs[3] = pCoef->G;
}
