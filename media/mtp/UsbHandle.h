/*
 * Copyright (C) 2007 The Android Open Source Project
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
#ifndef _USB_HANDLE_H
#define _USB_HANDLE_H

#include <linux/usb/f_mtp.h>

class UsbHandle {
    public:
        virtual int read(void *data, int len) = 0;
        virtual int write(const void *data, int len) = 0;

        virtual int receiveFile(mtp_file_range mfr) = 0;
        virtual int sendFile(mtp_file_range mfr) = 0;
        virtual int sendEvent(mtp_event me) = 0;

        virtual int start() = 0;
        virtual int close() = 0;

        virtual int configure(bool ptp) = 0;

        virtual ~UsbHandle() {};
};

UsbHandle *get_ffs_handle();
UsbHandle *get_mtp_handle();
extern UsbHandle *handle;

#define USB_FFS_MTP_PATH  "/dev/usb-ffs/mtp/"
#define USB_FFS_MTP_EP(x) USB_FFS_MTP_PATH#x
#define USB_FFS_MTP_EP0   USB_FFS_MTP_EP(ep0)

inline void usb_init(bool ptp) {
    if (handle == NULL) {
        bool ffs_ok = access(USB_FFS_MTP_EP0, W_OK) == 0;
        handle = ffs_ok ? get_ffs_handle() : get_mtp_handle();
    }

    handle->configure(ptp);
}
#endif // _USB_HANDLE_H

