/*
 * Copyright 2021 The Android Open Source Project
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

import android.media.SpatializationLevel;
import android.media.SpatializerHeadTrackingMode;

/**
 * The ISpatializer interface is used to control the native audio service implementation
 * of the spatializer stage with headtracking when present on a platform.
 * It is intended for exclusive use by the java AudioService running in system_server.
 * It provides APIs to discover the feature availability and options as well as control and report
 * the active state and modes of the spatializer and head tracking effect.
 * {@hide}
 */
interface ISpatializer {
    /** Releases a ISpatializer interface previously acquired. */
    void release();

    /** Reports the list of supported spatialization levels (see SpatializationLevel.aidl).
     * The list should never be empty if an ISpatializer interface was successfully
     * retrieved with IAudioPolicyService.getSpatializer().
     */
    SpatializationLevel[] getSupportedLevels();

    /** Selects the desired spatialization level (see SpatializationLevel.aidl). Selecting a level
     * different from SpatializationLevel.NONE with create the specialized multichannel output
     * mixer, create and enable the spatializer effect and let the audio policy attach eligible
     * AudioTrack to this output stream.
     */
    void setLevel(SpatializationLevel level);

    /** Gets the selected spatialization level (see SpatializationLevel.aidl) */
    SpatializationLevel getLevel();

    /** Reports the list of supported head tracking modes (see SpatializerHeadTrackingMode.aidl).
     * The list can be empty if the spatializer implementation does not support head tracking or if
     * no head tracking device is connected.
     */
    SpatializerHeadTrackingMode[] getSupportedHeadTrackingModes();

    /** Selects the desired head tracking mode (see SpatializerHeadTrackingMode.aidl) */
    void setDesiredHeadTrackingMode(SpatializerHeadTrackingMode mode);

    /** Gets the actual head tracking mode. Can be different from the desired mode if conditions to
     * enable the desired mode are not met (e.g if the head tracking device was removed)
     */
    SpatializerHeadTrackingMode getActualHeadTrackingMode();

    /** Reset the head tracking algorithm to consider current head pose as neutral */
    void recenterHeadTracker();

    /** Set the screen to stage transform to use by the head tracking algorithm */
    void setGlobalTransform(in float[] screenToStage);
}
