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

#ifndef __LVCS_BYPASSMIX_H__
#define __LVCS_BYPASSMIX_H__



/************************************************************************************/
/*                                                                                  */
/*    Includes                                                                      */
/*                                                                                  */
/************************************************************************************/

#include "LVC_Mixer.h"


/************************************************************************************/
/*                                                                                  */
/*    Structures                                                                    */
/*                                                                                  */
/************************************************************************************/

/* Bypass mixer structure */
typedef struct
{
    /* Mixer settings */
#ifdef BUILD_FLOAT
    LVMixer3_2St_FLOAT_st   Mixer_Instance;             /* Mixer instance */
#else
    LVMixer3_2St_st         Mixer_Instance;             /* Mixer instance */
#endif
    LVM_UINT16              Output_Shift;               /* Correcting gain output shift */

} LVCS_BypassMix_t;

#ifndef BUILD_FLOAT
/* Output gain type */
typedef struct
{
    /* Output gain settings, Gain = (Loss/32768) * 2^Shift */
    LVM_UINT16              Shift;                      /* Left shifts required */
    LVM_UINT16              Loss;                       /* Loss required */
    LVM_UINT16              UnprocLoss;                 /* Unprocessed path loss */
} Gain_t;
#else
typedef struct
{
    /* Output gain settings, Gain = (Loss/32768) * 2^Shift */
    LVM_UINT16             Shift;                      /* Left shifts required */
    LVM_FLOAT              Loss;                       /* Loss required */
    LVM_FLOAT              UnprocLoss;                 /* Unprocessed path loss */
} Gain_t;
#endif
/************************************************************************************/
/*                                                                                    */
/*    Function prototypes                                                                */
/*                                                                                    */
/************************************************************************************/

LVCS_ReturnStatus_en LVCS_BypassMixInit(LVCS_Handle_t       hInstance,
                                           LVCS_Params_t    *pParams);

#ifndef BUILD_FLOAT
LVCS_ReturnStatus_en LVCS_BypassMixer(LVCS_Handle_t         hInstance,
                                      const LVM_INT16       *pProcessed,
                                      const LVM_INT16       *unProcessed,
                                      LVM_INT16       *pOutData,
                                      LVM_UINT16      NumSamples);
#else
LVCS_ReturnStatus_en LVCS_BypassMixer(LVCS_Handle_t         hInstance,
                                      const LVM_FLOAT       *pProcessed,
                                      const LVM_FLOAT       *unProcessed,
                                      LVM_FLOAT       *pOutData,
                                      LVM_UINT16      NumSamples);
#endif

#endif  /* BYPASSMIX_H */
