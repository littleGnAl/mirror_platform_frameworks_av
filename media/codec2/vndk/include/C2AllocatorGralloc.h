/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef STAGEFRIGHT_CODEC2_ALLOCATOR_GRALLOC_H_
#define STAGEFRIGHT_CODEC2_ALLOCATOR_GRALLOC_H_

#include <functional>

#include <C2Buffer.h>
#include <C2Config.h>

namespace android {

/**
 * Unwrap the native handle from a Codec2 handle allocated by C2AllocatorGralloc.
 *
 * @param handle a handle allocated by C2AllocatorGralloc. This includes handles returned for a
 * graphic block allocation handle returned.
 *
 * @return a new NON-OWNING native handle that must be deleted using native_handle_delete.
 */
native_handle_t *UnwrapNativeCodec2GrallocHandle(const C2Handle *const handle);

/**
 * Wrap the gralloc handle and metadata into Codec2 handle recognized by
 * C2AllocatorGralloc.
 *
 * @return a new NON-OWNING C2Handle that must be closed and deleted using native_handle_close and
 * native_handle_delete.
 */
C2Handle *WrapNativeCodec2GrallocHandle(
        const native_handle_t *const handle,
        uint32_t width, uint32_t height, uint32_t format, uint64_t usage, uint32_t stride,
        uint32_t generation = 0, uint64_t igbp_id = 0, uint32_t igbp_slot = 0);

/**
 * When the gralloc handle is migrated to another bufferqueue, update
 * bufferqueue information.
 *
 * @return {@code true} when native_handle is a wrapped codec2 handle.
 */
bool MigrateNativeCodec2GrallocHandle(
        native_handle_t *handle,
        uint32_t generation, uint64_t igbp_id, uint32_t igbp_slot);

/**
 * \todo Get this from the buffer
 */
void _UnwrapNativeCodec2GrallocMetadata(
        const C2Handle *const handle,
        uint32_t *width, uint32_t *height, uint32_t *format, uint64_t *usage, uint32_t *stride,
        uint32_t *generation, uint64_t *igbp_id, uint32_t *igbp_slot);

/**
 * Get HDR metadata from Gralloc4 handle.
 *
 * \param[in]   handle      handle of the allocation
 * \param[out]  staticInfo  HDR static info to be filled. Ignored if null;
 *                          if |handle| is invalid or does not contain the metadata,
 *                          the shared_ptr is reset.
 * \param[out]  dynamicInfo HDR dynamic info to be filled. Ignored if null;
 *                          if |handle| is invalid or does not contain the metadata,
 *                          the shared_ptr is reset.
 * \return C2_OK if successful
 */
c2_status_t GetHdrMetadataFromGralloc4Handle(
        const C2Handle *const handle,
        std::shared_ptr<C2StreamHdrStaticInfo::input> *staticInfo,
        std::shared_ptr<C2StreamHdrDynamicInfo::input> *dynamicInfo);

/**
 * Set HDR metadata to Gralloc4 handle.
 *
 * \param[in]   staticInfo  HDR static info to set. Ignored if null or invalid.
 * \param[in]   dynamicInfo HDR dynamic info to set. Ignored if null or invalid.
 * \param[out]  handle      handle of the allocation.
 * \return C2_OK if successful
 */
c2_status_t SetHdrMetadataToGralloc4Handle(
        const std::shared_ptr<const C2StreamHdrStaticInfo::output> &staticInfo,
        const std::shared_ptr<const C2StreamHdrDynamicInfo::output> &dynamicInfo,
        const C2Handle *const handle);

class C2AllocatorGralloc : public C2Allocator {
public:
    virtual id_t getId() const override;

    virtual C2String getName() const override;

    virtual std::shared_ptr<const Traits> getTraits() const override;

    virtual c2_status_t newGraphicAllocation(
            uint32_t width, uint32_t height, uint32_t format, C2MemoryUsage usage,
            std::shared_ptr<C2GraphicAllocation> *allocation) override;

    virtual c2_status_t priorGraphicAllocation(
            const C2Handle *handle,
            std::shared_ptr<C2GraphicAllocation> *allocation) override;

    C2AllocatorGralloc(id_t id, bool bufferQueue = false);

    c2_status_t status() const;

    virtual ~C2AllocatorGralloc() override;

    virtual bool checkHandle(const C2Handle* const o) const override { return CheckHandle(o); }

    static bool CheckHandle(const C2Handle* const o);

    // deprecated
    static bool isValid(const C2Handle* const o) { return CheckHandle(o); }

private:
    class Impl;
    Impl *mImpl;
};

} // namespace android

#endif // STAGEFRIGHT_CODEC2_ALLOCATOR_GRALLOC_H_
