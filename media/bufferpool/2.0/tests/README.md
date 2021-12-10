# Bufferpool Tests

## Benchmark

The BenchmarkBufferpoolTest analyses the time taken for buffer operations such as allocate or map.
It is used to benchmark ion, dma and gralloc buffers when caching is enabled and disabled.
Benchmark results are published as a CSV report.

Run the following steps to build the test suite:
```
mm BenchmarkBufferpoolTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/BenchmarkBufferpoolTest/BenchmarkBufferpoolTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/BenchmarkBufferpoolTest/BenchmarkBufferpoolTest /data/local/tmp/
```

usage: BenchmarkBufferpoolTest
```
adb shell /data/local/tmp/BenchmarkBufferpoolTest
```
Alternatively, the test can also be run using atest command.

```
atest BenchmarkBufferpoolTest
```

# Analysis

The benchmark results are stored in a CSV file which can be used for analysis. These results are stored in following format:
BenchmarkBufferpool_currentTimestamp.csv

Note: This timestamp is in nano seconds and will change based on current system time.

The location of the CSV file is at /data/local/tmp/ and this file can be pulled from the device using the "adb pull" command.

```
adb pull /data/local/tmp/BenchmarkBufferpool_114134486592511.csv ./
```

## CSV Columns

Following columns are available in CSV.

Note: All time values are in nano seconds

1. **BufferType** : Describes the type of buffer allocated/mapped (i.e. linear/graphic).

2. **Operation** : Describes the current operation performed i.e. allocate/map.

3. **UsageFlag** : The Usage flag used while allocating/mapping the buffer.

4. **CacheDisabled** : To determine whether the cache flag is enabled(value 0) or disabled(value 1).

5. **Capacity** : Size of the buffer allocated.

6. **AvgTime(ns)** : The time taken to perform the current operation on the given buffer type. This time is averaged across 10 runs and measured in nanoseconds.
