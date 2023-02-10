/*
 * Copyright (C) 2023 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_TOMBSTONE_H_
#define ANDROID_SERVERS_CAMERA_TOMBSTONE_H_

#include <cstdlib>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/unique_fd.h>
#include <debuggerd/client.h>

namespace android {
namespace camera3 {

// Collect a debuggerd dumpstate of a given process and print out with ALOG
class CameraTombstone {
   public:
    /**
     * Prints all dumpstate of a given process with ALOG.
     */
    static void dump(pid_t pid);

   private:
    static std::thread spawn_redirect_thread(base::unique_fd fd);

    CameraTombstone();
    ~CameraTombstone();
    CameraTombstone(CameraTombstone& rhs);

};  // class CameraTraces

};  // namespace camera3
};  // namespace android

#endif  // ANDROID_SERVERS_CAMERA_TOMBSTONE_H_
