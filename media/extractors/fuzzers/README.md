# Fuzzer for extractors

## Table of contents
1. [libextractorbase](#extractorBase)

# <a name="extractorBase"></a> Fuzzer for libextractorbase
All the extractors have a common API - creating a data source, extraction
of all the tracks, etc. These common APIs have been abstracted in a base class
called `ExtractorBase` to ensure code is reused between fuzzer plugins.

Additionally, `ExtractorBase` also has support for memory based buffer
`BufferSource` since the fuzzing engine feeds data using memory buffers and
usage of standard data source objects like FileSource, HTTPSource, etc. is
not feasible.


## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
