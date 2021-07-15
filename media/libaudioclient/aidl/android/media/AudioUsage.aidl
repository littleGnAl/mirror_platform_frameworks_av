/*
 * Copyright (C) 2020 The Android Open Source Project
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
package android.media;

/**
 * {@hide}
 */
@Backing(type="int")
enum AudioUsage {
    UNKNOWN = 0,
    MEDIA = 1,
    VOICE_COMMUNICATION = 2,
    VOICE_COMMUNICATION_SIGNALLING = 3,
    ALARM = 4,
    NOTIFICATION = 5,
    NOTIFICATION_TELEPHONY_RINGTONE = 6,
    NOTIFICATION_COMMUNICATION_REQUEST = 7,
    NOTIFICATION_COMMUNICATION_INSTANT = 8,
    NOTIFICATION_COMMUNICATION_DELAYED = 9,
    NOTIFICATION_EVENT = 10,
    ASSISTANCE_ACCESSIBILITY = 11,
    ASSISTANCE_NAVIGATION_GUIDANCE = 12,
    ASSISTANCE_SONIFICATION = 13,
    GAME = 14,
    VIRTUAL_SOURCE = 15,
    ASSISTANT = 16,
    CALL_ASSISTANT = 17,
    EMERGENCY = 1000,
    SAFETY = 1001,
    VEHICLE_STATUS = 1002,
    ANNOUNCEMENT = 1003,
}
