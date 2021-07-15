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

#include "LVM_Types.h"
#include "LVM_Macros.h"
#include "ScalarArithmetic.h"

/*-------------------------------------------------------------------------*/
/* FUNCTION:                                                               */
/*   LVM_Polynomial                                                        */
/*                                                                         */
/* DESCRIPTION:                                                            */
/*   This function performs polynomial expansion                           */
/*  Y = (A0 + A1*X + A2*X2 + A3*X3 + �.. + AN*xN) << AN+1                  */
/*                                                                         */
/*  LVM_INT32 LVM_Polynomial(LVM_UINT16    N,                              */
/*                           LVM_INT32    *pCoefficients,                  */
/*                           LVM_INT32    X)                               */
/*                                                                         */
/* PARAMETERS:                                                             */
/*                                                                         */
/*  N                is the polynomial order                               */
/*  pCoefficients    is the ptr to polynomial coefficients A0,A1.. in Q.31 */
/*  X                is the input variable                                 */
/*                                                                         */
/* RETURNS:                                                                */
/*   The result of the polynomial expansion in Q1.31 format                */
/*-------------------------------------------------------------------------*/
LVM_FLOAT LVM_Polynomial(LVM_UINT16 N, LVM_FLOAT* pCoefficients, LVM_FLOAT X) {
    LVM_INT32 i;
    LVM_FLOAT Y, A, XTemp, Temp, sign;

    Y = *pCoefficients; /* Y=A0*/
    pCoefficients++;

    if (X == -1.0f) {
        Temp = -1;
        sign = Temp;
        for (i = 1; i <= N; i++) {
            Y += ((*pCoefficients) * sign);
            pCoefficients++;
            sign *= Temp;
        }

    } else {
        XTemp = X;
        for (i = N - 1; i >= 0; i--) {
            A = *pCoefficients;
            pCoefficients++;

            Temp = A * XTemp;
            Y += Temp;

            Temp = XTemp * X;
            XTemp = Temp;
        }
    }
    return Y;
}
