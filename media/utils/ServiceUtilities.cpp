/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "ServiceUtilities"

#include <binder/AppOpsManager.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include "mediautils/ServiceUtilities.h"

#include <iterator>
#include <algorithm>

/* When performing permission checks we do not use permission cache for
 * runtime permissions (protection level dangerous) as they may change at
 * runtime. All other permissions (protection level normal and dangerous)
 * can be cached as they never change. Of course all permission checked
 * here are platform defined.
 */

namespace android {

static const String16 sAndroidPermissionRecordAudio("android.permission.RECORD_AUDIO");
static const String16 sModifyPhoneState("android.permission.MODIFY_PHONE_STATE");
static const String16 sModifyAudioRouting("android.permission.MODIFY_AUDIO_ROUTING");

static String16 resolveCallingPackage(PermissionController& permissionController,
        const String16& opPackageName, uid_t uid) {
    if (opPackageName.size() > 0) {
        return opPackageName;
    }
    // In some cases the calling code has no access to the package it runs under.
    // For example, code using the wilhelm framework's OpenSL-ES APIs. In this
    // case we will get the packages for the calling UID and pick the first one
    // for attributing the app op. This will work correctly for runtime permissions
    // as for legacy apps we will toggle the app op for all packages in the UID.
    // The caveat is that the operation may be attributed to the wrong package and
    // stats based on app ops may be slightly off.
    Vector<String16> packages;
    permissionController.getPackagesForUid(uid, packages);
    if (packages.isEmpty()) {
        ALOGE("No packages for uid %d", uid);
        return opPackageName; // empty string
    }
    return packages[0];
}

static bool checkRecordingInternal(const String16& opPackageName, pid_t pid,
        uid_t uid, bool start) {
    // Okay to not track in app ops as audio server is us and if
    // device is rooted security model is considered compromised.
    if (isAudioServerOrRootUid(uid)) return true;

    // We specify a pid and uid here as mediaserver (aka MediaRecorder or StageFrightRecorder)
    // may open a record track on behalf of a client.  Note that pid may be a tid.
    // IMPORTANT: DON'T USE PermissionCache - RUNTIME PERMISSIONS CHANGE.
    PermissionController permissionController;
    const bool ok = permissionController.checkPermission(sAndroidPermissionRecordAudio, pid, uid);
    if (!ok) {
        ALOGE("Request requires %s", String8(sAndroidPermissionRecordAudio).c_str());
        return false;
    }

    String16 resolvedOpPackageName = resolveCallingPackage(
            permissionController, opPackageName, uid);
    if (resolvedOpPackageName.size() == 0) {
        return false;
    }

    AppOpsManager appOps;
    const int32_t op = appOps.permissionToOpCode(sAndroidPermissionRecordAudio);
    if (start) {
        if (appOps.startOpNoThrow(op, uid, resolvedOpPackageName, /*startIfModeDefault*/ false)
                != AppOpsManager::MODE_ALLOWED) {
            ALOGE("Request denied by app op: %d", op);
            return false;
        }
    } else {
        if (appOps.checkOp(op, uid, resolvedOpPackageName) != AppOpsManager::MODE_ALLOWED) {
            ALOGE("Request denied by app op: %d", op);
            return false;
        }
    }

    return true;
}

bool recordingAllowed(const String16& opPackageName, pid_t pid, uid_t uid) {
    return checkRecordingInternal(opPackageName, pid, uid, /*start*/ false);
}

bool startRecording(const String16& opPackageName, pid_t pid, uid_t uid) {
     return checkRecordingInternal(opPackageName, pid, uid, /*start*/ true);
}

void finishRecording(const String16& opPackageName, uid_t uid) {
    // Okay to not track in app ops as audio server is us and if
    // device is rooted security model is considered compromised.
    if (isAudioServerOrRootUid(uid)) return;

    PermissionController permissionController;
    String16 resolvedOpPackageName = resolveCallingPackage(
            permissionController, opPackageName, uid);
    if (resolvedOpPackageName.size() == 0) {
        return;
    }

    AppOpsManager appOps;
    const int32_t op = appOps.permissionToOpCode(sAndroidPermissionRecordAudio);
    appOps.finishOp(op, uid, resolvedOpPackageName);
}

bool captureAudioOutputAllowed(pid_t pid, uid_t uid) {
    if (isAudioServerOrRootUid(uid)) return true;
    static const String16 sCaptureAudioOutput("android.permission.CAPTURE_AUDIO_OUTPUT");
    bool ok = PermissionCache::checkPermission(sCaptureAudioOutput, pid, uid);
    if (!ok) ALOGV("Request requires android.permission.CAPTURE_AUDIO_OUTPUT");
    return ok;
}

bool captureMediaOutputAllowed(pid_t pid, uid_t uid) {
    if (isAudioServerOrRootUid(uid)) return true;
    static const String16 sCaptureMediaOutput("android.permission.CAPTURE_MEDIA_OUTPUT");
    bool ok = PermissionCache::checkPermission(sCaptureMediaOutput, pid, uid);
    if (!ok) ALOGE("Request requires android.permission.CAPTURE_MEDIA_OUTPUT");
    return ok;
}

bool captureHotwordAllowed(const String16& opPackageName, pid_t pid, uid_t uid) {
    // CAPTURE_AUDIO_HOTWORD permission implies RECORD_AUDIO permission
    bool ok = recordingAllowed(opPackageName, pid, uid);

    if (ok) {
        static const String16 sCaptureHotwordAllowed("android.permission.CAPTURE_AUDIO_HOTWORD");
        // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
        ok = PermissionCache::checkPermission(sCaptureHotwordAllowed, pid, uid);
    }
    if (!ok) ALOGV("android.permission.CAPTURE_AUDIO_HOTWORD");
    return ok;
}

bool settingsAllowed() {
    // given this is a permission check, could this be isAudioServerOrRootUid()?
    if (isAudioServerUid(IPCThreadState::self()->getCallingUid())) return true;
    static const String16 sAudioSettings("android.permission.MODIFY_AUDIO_SETTINGS");
    // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
    bool ok = PermissionCache::checkCallingPermission(sAudioSettings);
    if (!ok) ALOGE("Request requires android.permission.MODIFY_AUDIO_SETTINGS");
    return ok;
}

bool modifyAudioRoutingAllowed() {
    // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
    bool ok = PermissionCache::checkCallingPermission(sModifyAudioRouting);
    if (!ok) ALOGE("android.permission.MODIFY_AUDIO_ROUTING");
    return ok;
}

bool modifyDefaultAudioEffectsAllowed() {
    static const String16 sModifyDefaultAudioEffectsAllowed(
            "android.permission.MODIFY_DEFAULT_AUDIO_EFFECTS");
    // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
    bool ok = PermissionCache::checkCallingPermission(sModifyDefaultAudioEffectsAllowed);

    if (!ok) ALOGE("android.permission.MODIFY_DEFAULT_AUDIO_EFFECTS");
    return ok;
}

bool dumpAllowed() {
    static const String16 sDump("android.permission.DUMP");
    // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
    bool ok = PermissionCache::checkCallingPermission(sDump);
    // convention is for caller to dump an error message to fd instead of logging here
    //if (!ok) ALOGE("Request requires android.permission.DUMP");
    return ok;
}

bool modifyPhoneStateAllowed(pid_t pid, uid_t uid) {
    bool ok = PermissionCache::checkPermission(sModifyPhoneState, pid, uid);
    ALOGE_IF(!ok, "Request requires %s", String8(sModifyPhoneState).c_str());
    return ok;
}

// privileged behavior needed by Dialer, Settings, SetupWizard and CellBroadcastReceiver
bool bypassInterruptionPolicyAllowed(pid_t pid, uid_t uid) {
    static const String16 sWriteSecureSettings("android.permission.WRITE_SECURE_SETTINGS");
    bool ok = PermissionCache::checkPermission(sModifyPhoneState, pid, uid)
        || PermissionCache::checkPermission(sWriteSecureSettings, pid, uid)
        || PermissionCache::checkPermission(sModifyAudioRouting, pid, uid);
    ALOGE_IF(!ok, "Request requires %s or %s",
             String8(sModifyPhoneState).c_str(), String8(sWriteSecureSettings).c_str());
    return ok;
}

status_t checkIMemory(const sp<IMemory>& iMemory)
{
    if (iMemory == 0) {
        ALOGE("%s check failed: NULL IMemory pointer", __FUNCTION__);
        return BAD_VALUE;
    }

    sp<IMemoryHeap> heap = iMemory->getMemory();
    if (heap == 0) {
        ALOGE("%s check failed: NULL heap pointer", __FUNCTION__);
        return BAD_VALUE;
    }

    off_t size = lseek(heap->getHeapID(), 0, SEEK_END);
    lseek(heap->getHeapID(), 0, SEEK_SET);

    if (iMemory->pointer() == NULL || size < (off_t)iMemory->size()) {
        ALOGE("%s check failed: pointer %p size %zu fd size %u",
              __FUNCTION__, iMemory->pointer(), iMemory->size(), (uint32_t)size);
        return BAD_VALUE;
    }

    return NO_ERROR;
}

sp<content::pm::IPackageManagerNative> MediaPackageManager::retreivePackageManager() {
    const sp<IServiceManager> sm = defaultServiceManager();
    if (sm == nullptr) {
        ALOGW("%s: failed to retrieve defaultServiceManager", __func__);
        return nullptr;
    }
    sp<IBinder> packageManager = sm->checkService(String16(nativePackageManagerName));
    if (packageManager == nullptr) {
        ALOGW("%s: failed to retrieve native package manager", __func__);
        return nullptr;
    }
    return interface_cast<content::pm::IPackageManagerNative>(packageManager);
}

std::optional<std::vector<string>, std::vector<bool>> MediaPackageManager::querryPM(uid_t uid) {
    if (mPackageManager == nullptr) {
        /** Can not fetch package manager at construction it may not yet be registered. */
        mPackageManager = retreivePackageManager();
        if (mPackageManager == nullptr) {
            ALOGW("%s: Playback capture is denied as package manager is not reachable", __func__);
            return std::nullopt;
        }
    }

    std::vector<std::string> packageNames;
    auto status = mPackageManager->getNamesForUids({(int32_t)uid}, &packageNames);
    if (!status.isOk()) {
        ALOGW("%s: Playback capture is denied for uid %u as the package names could not be "
              "retrieved from the package manager: %s", __func__, uid, status.toString8().c_str());
        return std::nullopt;
    }
    if (packageNames.empty()) {
        ALOGW("%s: Playback capture for uid %u is denied as no package name could be retrieved "
              "from the package manager: %s", __func__, uid, status.toString8().c_str());
        return std::nullopt;
    }
    std::vector<bool> isAllowed;
    status = mPackageManager->isAudioPlaybackCaptureAllowed(packageNames, &isAllowed);
    if (!status.isOk()) {
        ALOGW("%s: Playback capture is denied for uid %u as the manifest property could not be "
              "retrieved from the package manager: %s", __func__, uid, status.toString8().c_str());
        return std::nullopt;
    }
    if (packageNames.size() != isAllowed.size()) {
        ALOGW("%s: Playback capture is denied for uid %u as the package manager returned incoherent"
              " response size: %zu != %zu", __func__, uid, packageNames.size(), isAllowed.size());
        return std::nullopt;
    }

    return {std::move(packageNames), std::move(isAllowed)};
}

std::optional<bool> MediaPackageManager::doIsAllowed(uid_t uid, pid_t pid) {
    // Lets first check if we have cached such request
    if (auto previousRequestIt = mPreviousRequests.find(pid);
        previousRequestIt != mPreviousRequests.end() && previousRequestIt->second == uid) {
        // It is virtually possible that an app was updated but kept its pid,
        // in that case we will not query the PM again.
        if (auto cacheIt = mCache.find(uid); cacheIt == mCache.end()) {
            // Should never happen
            ALOGE("%s: Request was made but not cached for uid/pid %u/%u!", __func__, uid, pid);
        } else {
           return cacheIt->second->playbackCaptureAllowed;
        }
    }

    auto response = querryPM(uid);
    if (!response) {
        return std::nullopt;
    }
    auto& [packageNames, isAllowed] = response;

    // Cache the PM response
    mPreviousRequests[pid] = uid;
    auto& uidCache = mCache[uid];
    // Zip together packageNames and isAllowed for debug logs
    Packages& packages = uidCache.packages;
    packages.resize(packageNames.size()); // Reuse all objects
    std::transform(begin(packageNames), end(packageNames), begin(isAllowed),
                   begin(packages), [] (auto& name, bool isAllowed) -> Package {
                       return {std::move(name), isAllowed};
                   });

    // Only allow playback record if all packages in this UID allow it
    bool playbackCaptureAllowed = std::all_of(begin(isAllowed), end(isAllowed),
                                                  [](bool b) { return b; });
    uidCache.playbackCaptureAllowed = playbackCaptureAllowed;
    return playbackCaptureAllowed;

}

void MediaPackageManager::dump(int fd, int spaces) const {
    dprintf(fd, "%*sAllow playback capture cache:\n", spaces, "");
    if (mPackageManager == nullptr) {
        dprintf(fd, "%*sNo package manager\n", spaces + 2, "");
    }
    dprintf(fd, "%*sPackage manager errors: %u\n", spaces + 2, "", mPackageManagerErrors);

    for (const auto& [uid, uidCache] : mCache) {
        auto boolToStr = [](bool b) { b ? "true " : "false" };
        dprintf(fd, "%*s- uid=%5u, allowPlaybackCapture=%s\n", spaces + 2, "",
                uid, boolToStr(uidCache.playbackCaptureAllowed));
        for (const auto& package : uidCache.packages) {
            dprintf(fd, "%*s         + allowPlaybackCapture=%s, packageName=%s\n", spaces + 2, "",
                    boolToStr(package.playbackCaptureAllowed), package.name.c_str());
        }
    }
    dprintf(fd, "%*sPackage manager cache valid for (uid/pid):\n", spaces + 2, "");
    for (auto& [uid, pid] = mPreviousRequests) {
        dprintf(fd, " %5u/%5u", uid, pid);
    }
    dprintf(fd, "\n");
}

} // namespace android
