/*
 * Copyright 2019 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "PipelineWatcher"

#include <numeric>

#include <log/log.h>

#include "PipelineWatcher.h"

namespace android {

PipelineWatcher &PipelineWatcher::inputDelay(uint32_t value) {
    mInputDelay = value;
    return *this;
}

PipelineWatcher &PipelineWatcher::pipelineDelay(uint32_t value) {
    mPipelineDelay = value;
    return *this;
}

PipelineWatcher &PipelineWatcher::outputDelay(uint32_t value) {
    mOutputDelay = value;
    return *this;
}

PipelineWatcher &PipelineWatcher::smoothnessFactor(uint32_t value) {
    mSmoothnessFactor = value;
    return *this;
}

void PipelineWatcher::onInputBufferRequested(size_t inputId) {
    auto result = mClientOwnedInputIds.insert(inputId);
    if (!result.second) {
        // input ID is already tracked
        ALOGW("onInputBufferRequested: input %zx is already owned by client per "
              "our record.", inputId);
    }
}

void PipelineWatcher::onWorkQueued(
        size_t inputId,
        uint64_t frameIndex,
        std::vector<std::shared_ptr<C2Buffer>> &&buffers,
        const Clock::time_point &queuedAt) {
    if (inputId != 0) {
        size_t erased = mClientOwnedInputIds.erase(inputId);
        if (erased == 0) {
            // input ID was not tracked
            ALOGW("onWorkQueued: input %zx is not owned by client per our record.", inputId);
        }
    }
    ALOGV("onWorkQueued(frameIndex=%llu, buffers(size=%zu), queuedAt=%lld)",
          (unsigned long long)frameIndex,
          buffers.size(),
          (long long)queuedAt.time_since_epoch().count());
    auto it = mFramesInPipeline.find(frameIndex);
    if (it != mFramesInPipeline.end()) {
        ALOGD("onWorkQueued: Duplicate frame index (%llu); previous entry removed",
              (unsigned long long)frameIndex);
        (void)mFramesInPipeline.erase(it);
    }
    (void)mFramesInPipeline.try_emplace(frameIndex, std::move(buffers), queuedAt);
}

std::shared_ptr<C2Buffer> PipelineWatcher::onInputBufferReleased(
        uint64_t frameIndex, size_t arrayIndex) {
    ALOGV("onInputBufferReleased(frameIndex=%llu, arrayIndex=%zu)",
          (unsigned long long)frameIndex, arrayIndex);
    auto it = mFramesInPipeline.find(frameIndex);
    if (it == mFramesInPipeline.end()) {
        ALOGD("onInputBufferReleased: frameIndex not found (%llu); ignored",
              (unsigned long long)frameIndex);
        return nullptr;
    }
    if (it->second.buffers.size() <= arrayIndex) {
        ALOGD("onInputBufferReleased: buffers at %llu: size %zu, requested index: %zu",
              (unsigned long long)frameIndex, it->second.buffers.size(), arrayIndex);
        return nullptr;
    }
    std::shared_ptr<C2Buffer> buffer(std::move(it->second.buffers[arrayIndex]));
    ALOGD_IF(!buffer, "onInputBufferReleased: buffer already released (%llu:%zu)",
             (unsigned long long)frameIndex, arrayIndex);
    return buffer;
}

void PipelineWatcher::onWorkDone(uint64_t frameIndex) {
    ALOGV("onWorkDone(frameIndex=%llu)", (unsigned long long)frameIndex);
    auto it = mFramesInPipeline.find(frameIndex);
    if (it == mFramesInPipeline.end()) {
        ALOGD("onWorkDone: frameIndex not found (%llu); ignored",
              (unsigned long long)frameIndex);
        return;
    }
    (void)mFramesInPipeline.erase(it);
}

void PipelineWatcher::flush() {
    ALOGV("flush");
    mFramesInPipeline.clear();
    mClientOwnedInputIds.clear();
}

bool PipelineWatcher::pipelineHasRoom() const {
    // Determine whether the pipeline needs more input.

    // Case 1: total # of frames in pipeline (including the buffers pending client input)
    // is larger than all delays + smoothness factor
    size_t numClientInputBuffers = mClientOwnedInputIds.size();
    if (numClientInputBuffers + mFramesInPipeline.size() >=
            mInputDelay + mPipelineDelay + mOutputDelay + mSmoothnessFactor) {
        ALOGV("pipelineNeedsMoreInput(%u/%u/%u): enough frames in pipeline (%zu) client %zu",
              mInputDelay, mPipelineDelay, mOutputDelay,
              mFramesInPipeline.size(), numClientInputBuffers);
        return false;
    }

    // Case 2: # of frames in pipeline with the input buffer released ---
    // in other words, frames past the input stage is larger than
    // pipeline + output delays, plus smoothness factor.
    size_t sizeWithInputReleased = std::count_if(
            mFramesInPipeline.begin(),
            mFramesInPipeline.end(),
            [](const decltype(mFramesInPipeline)::value_type &value) {
                for (const std::shared_ptr<C2Buffer> &buffer : value.second.buffers) {
                    if (buffer) {
                        return false;
                    }
                }
                return true;
            });
    if (sizeWithInputReleased >=
            mPipelineDelay + mOutputDelay + mSmoothnessFactor) {
        ALOGV("pipelineNeedsMoreInput(%u/%u/%u): "
              "enough frames in pipeline, with input released (%zu)",
              mInputDelay, mPipelineDelay, mOutputDelay, sizeWithInputReleased);
        return false;
    }

    // Case 3: # of frames in pipeline with the input buffer pending
    // (including the buffers pending client input) ---
    // in other words, frames before the output delay is larger than
    // input + pipeline delays, plus smoothness factor.
    size_t sizeWithInputsPending =
        numClientInputBuffers + mFramesInPipeline.size() - sizeWithInputReleased;
    if (sizeWithInputsPending > mPipelineDelay + mInputDelay + mSmoothnessFactor) {
        ALOGV("pipelineNeedsMoreInput(%u/%u/%u): enough inputs pending (%zu) in pipeline, "
              "with inputs released (%zu)",
              mInputDelay, mPipelineDelay, mOutputDelay,
              sizeWithInputsPending, sizeWithInputReleased);
        return false;
    }
    ALOGV("pipeline (%u/%u/%u) has room (client %zu, pipeline: %zu, input released: %zu)",
          mInputDelay, mPipelineDelay, mOutputDelay,
          numClientInputBuffers, mFramesInPipeline.size(), sizeWithInputReleased);
    return true;
}

PipelineWatcher::Clock::duration PipelineWatcher::elapsed(
        const PipelineWatcher::Clock::time_point &now, size_t n) const {
    if (mFramesInPipeline.size() <= n) {
        return Clock::duration::zero();
    }
    std::vector<Clock::duration> durations;
    for (const decltype(mFramesInPipeline)::value_type &value : mFramesInPipeline) {
        Clock::duration elapsed = now - value.second.queuedAt;
        ALOGV("elapsed: frameIndex = %llu elapsed = %lldms",
              (unsigned long long)value.first,
              std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
        durations.push_back(elapsed);
    }
    std::nth_element(durations.begin(), durations.begin() + n, durations.end(),
                     std::greater<Clock::duration>());
    return durations[n];
}

}  // namespace android
