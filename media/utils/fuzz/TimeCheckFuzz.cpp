#include "fuzzer/FuzzedDataProvider.h"
#include "mediautils/TimeCheck.h"

static constexpr int kMaxStringLen = 256;
// While it might be interesting to test long-running
// jobs, it seems unlikely it'd lead to the types of crashes
// we're looking for, and would mean a significant increase in fuzzer time.
// Therefore, we are setting a cap to 2x the default value.
static constexpr uint32_t kMaxTimeout = 10000;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider data_provider(data, size);
  uint32_t timeout =
      data_provider.ConsumeIntegralInRange<uint32_t>(0, kMaxTimeout);
  std::string name = data_provider.ConsumeRandomLengthString(kMaxStringLen);
  // There's essentially 5 operations that we can access in this class
  // 1. The constructor, which is fuzzed here:
  android::TimeCheck timeCheck(name.c_str(), timeout);

  // 2. The time it takes to run this operation. As mentioned above,
  //    long-running tasks are not good for fuzzing, but there will be
  //    some flucation based on pid_size.
  uint8_t pid_size = data_provider.ConsumeIntegral<uint8_t>();
  std::vector<pid_t> pids;
  for (uint8_t i = 0; i < pid_size; i++) {
    pids.push_back(data_provider.ConsumeIntegral<pid_t>());
  }
  // 3. We also have setAudioHalPids, which is populated with the pids set
  // above.
  android::TimeCheck::setAudioHalPids(pids);

  // 4. Accessing those pids (assinged to variable so it can be deconstructed)
  android::TimeCheck::getAudioHalPids();

  // Finally, the destructor on timecheck. These seem to be the only factors in
  // play.
  return 0;
}
