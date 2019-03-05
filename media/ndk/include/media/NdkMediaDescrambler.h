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

/*
 * This file defines an NDK API.
 * Do not remove methods.
 * Do not change method signatures.
 * Do not change the value of constants.
 * Do not change the size of any of the classes defined in here.
 * Do not reference types that are not part of the NDK.
 * Do not #include files that aren't part of the NDK.
 */

#ifndef _NDK_MEDIA_DESCRAMBLER_H
#define _NDK_MEDIA_DESCRAMBLER_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/cdefs.h>

#include "NdkMediaError.h"
#include "NdkMediaCas.h"
#include "NdkMediaCodec.h"

__BEGIN_DECLS

#if __ANDROID_API__ >= __ANDROID_API_FUTURE__

struct AMediaDescrambler;
typedef struct AMediaDescrambler AMediaDescrambler;

typedef enum _AMediaDescramblerDecoderSecurity {
        kAMediaDescrambler_UnsecureDecoder = 0,
        kAMediaDescrambler_SecureDecoder   = 1,
} AMediaDescramblerDecoderSecurity;


typedef enum _AMediaDescramblerScramblingFlags {
        kAMediaDescrambler_Scrambling_Flag_PesHeader  = (1 << 31)
} AMediaDescramblerScramblingFlags;

#define SCRAMBLE_FLAG_PES_HEADER 0x00000001

AMediaDescrambler* AMediaDescrambler_create(const int32_t id);
void AMediaDescrambler_release(AMediaDescrambler *);

media_status_t AMediaDescrambler_setMediaCasSession(AMediaDescrambler *, AMediaCasSessionId *sessionId);
media_status_t AMediaDescrambler_requiresSecureDecoderComponent(AMediaDescrambler *, const char *mime, int *success);
media_status_t AMediaDescrambler_descramble(AMediaDescrambler *mObj,
                                            const void *srcPtr,
                                            int32_t srcOffset,
                                            void *dstPtr,
                                            int32_t dstOffset,
                                            AMediaCodecCryptoInfo* cryptoInfo,
                                            uint32_t *bytesWritten);

#endif /* __ANDROID_API__ >= __ANDROID_API_FUTURE__ */

__END_DECLS

#endif //_NDK_MEDIA_DESCRAMBLER_H