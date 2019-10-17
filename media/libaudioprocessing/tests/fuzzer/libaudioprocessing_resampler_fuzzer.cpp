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

#include <android-base/macros.h>
#include <audio_utils/primitives.h>
#include <audio_utils/sndfile.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <media/AudioBufferProvider.h>
#include <media/AudioResampler.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utils/Vector.h>

using namespace android;

class Provider : public AudioBufferProvider {
  const void* mAddr;        // base address
  const size_t mNumFrames;  // total frames
  const size_t mFrameSize;  // size of each frame in bytes
  size_t mNextFrame;        // index of next frame to provide
  size_t mUnrel;            // number of frames not yet released
 public:
  Provider(const void* addr, size_t frames, size_t frameSize)
      : mAddr(addr),
        mNumFrames(frames),
        mFrameSize(frameSize),
        mNextFrame(0),
        mUnrel(0) {}
  virtual status_t getNextBuffer(Buffer* buffer) {
    size_t requestedFrames = buffer->frameCount;
    if (requestedFrames > mNumFrames - mNextFrame) {
      buffer->frameCount = mNumFrames - mNextFrame;
    }
    mUnrel = buffer->frameCount;
    if (buffer->frameCount > 0) {
      buffer->raw = (char*)mAddr + mFrameSize * mNextFrame;
      return NO_ERROR;
    } else {
      buffer->raw = NULL;
      return NOT_ENOUGH_DATA;
    }
  }
  virtual void releaseBuffer(Buffer* buffer) {
    if (buffer->frameCount > mUnrel) {
      mNextFrame += mUnrel;
      mUnrel = 0;
    } else {
      mNextFrame += buffer->frameCount;
      mUnrel -= buffer->frameCount;
    }
    buffer->frameCount = 0;
    buffer->raw = NULL;
  }
  void reset() { mNextFrame = 0; }
};

AudioResampler::src_quality qualities[] = {
    AudioResampler::DEFAULT_QUALITY,   AudioResampler::LOW_QUALITY,
    AudioResampler::MED_QUALITY,       AudioResampler::HIGH_QUALITY,
    AudioResampler::VERY_HIGH_QUALITY, AudioResampler::DYN_LOW_QUALITY,
    AudioResampler::DYN_MED_QUALITY,   AudioResampler::DYN_HIGH_QUALITY};

int parseValue(const uint8_t* src, int index, void* dst, size_t size) {
  memcpy(dst, &src[index], size);
  return size;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  int input_freq = 0;
  int output_freq = 0;
  int input_channels = 0;

  float left_volume = 0;
  float right_volume = 0;

  size_t metadata_size = 1 + 3 * sizeof(int) + 2 * sizeof(float);
  if (size < metadata_size) {
    // not enough data to set options
    return 0;
  }

  AudioResampler::src_quality quality = qualities[data[0] % 8];

  int index = 1;

  index += parseValue(data, index, &input_freq, sizeof(int));
  index += parseValue(data, index, &output_freq, sizeof(int));
  index += parseValue(data, index, &input_channels, sizeof(int));

  index += parseValue(data, index, &left_volume, sizeof(float));
  index += parseValue(data, index, &right_volume, sizeof(float));

  if (input_freq <= 0 || output_freq <= 0) {
    // sampling frequencies must be positive
    return 0;
  }

  if (input_channels < 1 ||
      input_channels > (quality < AudioResampler::DYN_LOW_QUALITY ? 2 : 8)) {
    // invalid number of input channels
    return 0;
  }

  size_t stream_size = size - metadata_size;
  uint8_t* stream_data = (uint8_t*)malloc(stream_size);
  memcpy(stream_data, &data[metadata_size], stream_size);

  AudioResampler* resampler = AudioResampler::create(
      AUDIO_FORMAT_PCM_16_BIT, input_channels, output_freq, quality);

  resampler->setSampleRate(input_freq);
  resampler->setVolume(left_volume, right_volume);

  size_t input_frame_size = input_channels * sizeof(int16_t);
  size_t input_frames = stream_size / input_frame_size;

  Provider provider(stream_data, input_frames, input_frame_size);

  // output is at least stereo samples
  int output_channels = input_channels > 2 ? input_channels : 2;
  size_t output_frame_size = output_channels * sizeof(int32_t);
  size_t output_frames = ((int32_t)input_frames * output_freq) / input_freq;
  size_t output_size = output_frames * output_frame_size;

  void* output_vaddr = malloc(output_size);

  for (size_t i = 0; i < output_frames; i++) {
    memset(output_vaddr, 0, output_size);
    resampler->resample((int*)output_vaddr, i, &provider);
  }

  resampler->reset();
  delete resampler;

  return 0;
}
