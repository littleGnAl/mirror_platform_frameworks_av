#include <fcntl.h>

#include <functional>

#include "fuzzer/FuzzedDataProvider.h"
#include "mediautils/ServiceUtilities.h"

static constexpr int kMaxOperations = 500;
static constexpr int kMaxStringLen = 256;

const std::vector<
    std::function<void(FuzzedDataProvider *, android::MediaPackageManager)>>
    operations = {
        [](FuzzedDataProvider *data_provider,
           android::MediaPackageManager pm) -> void {
          uid_t uid = data_provider->ConsumeIntegral<uid_t>();
          pm.allowPlaybackCapture(uid);
        },
        [](FuzzedDataProvider *data_provider,
           android::MediaPackageManager pm) -> void {
          int spaces = data_provider->ConsumeIntegral<int>();

          // Dump everything into /dev/null
          int fd = open("/dev/null", O_WRONLY);
          pm.dump(fd, spaces);
          close(fd);
        },
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider data_provider(data, size);
  uid_t uid = data_provider.ConsumeIntegral<uid_t>();
  pid_t pid = data_provider.ConsumeIntegral<pid_t>();

  // There is not state here, and order is not significant,
  // so we can simply call all of the target functions
  android::isServiceUid(uid);
  android::isAudioServerUid(uid);
  android::isAudioServerOrSystemServerUid(uid);
  android::isAudioServerOrSystemServerOrRootUid(uid);
  android::isAudioServerOrMediaServerUid(uid);
  std::string packageNameStr =
      data_provider.ConsumeRandomLengthString(kMaxStringLen);
  android::String16 opPackageName(packageNameStr.c_str());
  recordingAllowed(opPackageName, pid, uid);
  startRecording(opPackageName, pid, uid);
  finishRecording(opPackageName, uid);
  android::captureAudioOutputAllowed(pid, uid);
  android::captureMediaOutputAllowed(pid, uid);
  android::captureHotwordAllowed(opPackageName, pid, uid);
  android::modifyPhoneStateAllowed(uid, pid);
  android::bypassInterruptionPolicyAllowed(uid, pid);
  android::settingsAllowed();
  android::modifyAudioRoutingAllowed();
  android::modifyDefaultAudioEffectsAllowed();
  android::dumpAllowed();

  // MediaPackageManager does have state, so we need the fuzzer to decide order
  android::MediaPackageManager packageManager;
  size_t ops_run = 0;
  while (data_provider.remaining_bytes() > 0 && ops_run++ < kMaxOperations) {
    uint8_t op =
        data_provider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
    operations[op](&data_provider, packageManager);
  }

  return 0;
}
