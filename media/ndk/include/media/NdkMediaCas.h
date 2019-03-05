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

#ifndef _NDK_MEDIA_CAS_H
#define _NDK_MEDIA_CAS_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/cdefs.h>

#include "NdkMediaError.h"

__BEGIN_DECLS


#if __ANDROID_API__ >= __ANDROID_API_FUTURE__
/**
 * AMediaCas is an opaque type that allows direct application access to CAS service.
 */
struct AMediaCas;
typedef struct AMediaCas AMediaCas;

typedef struct AMediaCasByteArray {
    const uint8_t *ptr;
    size_t length;
} AMediaCasByteArray;

typedef AMediaCasByteArray AMediaCasData;
typedef AMediaCasByteArray AMediaCasSessionId;
typedef AMediaCasByteArray AMediaCasEmm;
typedef AMediaCasByteArray AMediaCasEcm;

typedef struct AMediaCasPluginDescriptor {
    int32_t CA_system_id;
    char*   CA_system_name;
} AMediaCasPluginDescriptor;

typedef struct AMediaCasPluginDescriptorArray {
    AMediaCasPluginDescriptor* descriptors;
    size_t length;
} AMediaCasPluginDescriptorArray;

/**
 * Signature of the callback which is called when a new event is arrives from {@link AMediaCas}.
 *
 * @param event An integer denoting a scheme-specific event to be sent.
 * @param eventData A byte array of data whose format and meaning are scheme-specific.
                    This value may be null.
 */
typedef void (*AMediaCas_EventCallback)(int32_t event, AMediaCasByteArray* eventData);

typedef struct AMediaCas_EventListener {

    AMediaCas_EventCallback onCasEvent;

} AMediaCas_EventListener;

/**
 * List all available CA plugins on the device.
 * 
 * @return {@link AMediaCasPluginDescriptorArray} list of all supported CA plugins.
 * 
 * NOTE: It is required to release returned array by calling {@link AMediaCas_releasePluginsArray}
 *       when done using the array.
 */
const AMediaCasPluginDescriptorArray* AMediaCas_enumeratePlugins(void);

/**
 * Release allocated memory of an AMediaCasPluginDescriptorArray returned by {@link AMediaCas_enumeratePlugins}
 * 
 * NOTE: must be called on returned array from {@link AMediaCas_enumeratePlugins} to prevent memory leaks.
 */
void AMediaCas_releasePluginsArray(const AMediaCasPluginDescriptorArray* mediaArray);

/**
 * Query if a certain CA system is supported on this device.
 * 
 * @param CA_system_id identifies the universal unique ID of the crypto scheme.
 * 
 * @return true if CA system is supported else false is returned.
 */
bool AMediaCas_isSystemIdSupported(const int32_t CA_system_id);

/**
 * Create a {@link AMediaCas} instance of specified system id.
 * 
 * @param CA_system_id identifies the universal unique ID of the crypto scheme.
 * 
 * @return {@link AMediaCas} pointer or NULL if CA system is unsupported.
 */
AMediaCas* AMediaCas_createByID(const int32_t CA_system_id);

/**
 * Delete a {@link AMediaCas} object and release all resources.
 */
media_status_t AMediaCas_close(AMediaCas* mediaCas);

/**
 * Set an event listener to receive notifications from the MediaCas instance.
 *
 * @param mediaCas The mediaCas of interest.
 * @param listener An instance of extended class of {@link AMediaCas_EventListener} to receive notifications from the media cas.
 */
media_status_t AMediaCas_setEventListener(AMediaCas* mediaCas, AMediaCas_EventListener* listener);

/**
 * Set the private data for the CA system.
 *
 * @param mediaCas The mediaCas of interest.
 * @param privateData private data to be set.
 */
media_status_t AMediaCas_setPrivateData(AMediaCas* mediaCas, const AMediaCasData* privateData);

/**
 * Open a session to descramble one or more streams scrambled by the conditional access system.
 *
 * @param mediaCas The mediaCas of interest.
 * @param sessionId If operation succeeded will be filled with session id later used to reference opened session.
 */
media_status_t AMediaCas_openSession(AMediaCas* mediaCas, /*out*/AMediaCasSessionId *sessionId);

/**
 * Closes previously opened session.
 *
 * @param mediaCas The mediaCas of interest.
 * @param sessionId The session to be closed.
 */
media_status_t AMediaCas_closeSession(AMediaCas* mediaCas, const AMediaCasSessionId* sessionId);

/**
 * Set the private data for a session.
 *
 * @param mediaCas The mediaCas of interest.
 * @param sessionId The session of interest.
 * @param privateData private data to be set.
 */
media_status_t AMediaCas_setSessionPrivateData(AMediaCas* mediaCas, const AMediaCasSessionId* sessionId, const AMediaCasData* privateData);

/**
 * Send a received ECM packet to the specified session of the CA system.
 *
 * @param mediaCas The mediaCas of interest.
 * @param sessionId The session of interest.
 * @param ecm The ECM data to be processed. This value must never be null.
 */
media_status_t AMediaCas_processEcm(AMediaCas* mediaCas, const AMediaCasSessionId* sessionId, const AMediaCasEcm* ecm);

/**
 * Send a received EMM packet to the CA system.
 *
 * @param mediaCas The mediaCas of interest.
 * @param emm The EMM data to be processed.
 */
media_status_t AMediaCas_processEmm(AMediaCas* mediaCas, const AMediaCasEmm* emm);

/**
 * Send an event to a CA system. The format of the event is scheme-specific and is opaque to the framework.
 *
 * @param mediaCas The mediaCas of interest.
 * @param event An integer denoting a scheme-specific event to be sent.
 * @param arg A scheme-specific integer argument for the event.
 * @param eventData A byte array containing scheme-specific data for the event. This value may be null.
 */
media_status_t AMediaCas_sendEvent(AMediaCas* mediaCas, int32_t event, int32_t arg, const AMediaCasData* eventData);

/**
 * Initiate a provisioning operation for a CA system.
 *
 * @param mediaCas The mediaCas of interest.
 * @param provisionString The string containing information needed for the provisioning operation, the format of which is scheme and implementation specific.
 */
media_status_t AMediaCas_provision(AMediaCas* mediaCas, const char* provisionString);

/**
 * Notify the CA system to refresh entitlement keys.
 *
 * @param mediaCas The mediaCas of interest.
 * @param refreshType The type of the refreshment.
 * @param refreshData Private data associated with the refreshment.
 */
media_status_t AMediaCas_refreshEntitlements(AMediaCas* mediaCas, int32_t refreshType, const AMediaCasData* refreshData);

#endif /* __ANDROID_API__ >= __ANDROID_API_FUTURE__ */

__END_DECLS

#endif //_NDK_MEDIA_CAS_H
