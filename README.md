This is a small project for fuzzing [Apache Commons Compress](https://commons.apache.org/proper/commons-compress/) 
with the [jazzer](https://github.com/CodeIntelligenceTesting/jazzer) fuzzing tool.

See [Fuzzing](https://en.wikipedia.org/wiki/Fuzzing) for a general description 
of the theory behind fuzzy testing.

Because Java uses a runtime environment which does not crash on invalid actions of an 
application (unless native code is invoked), Fuzzing of Java-based applications  
focuses on the following:

* verify if only expected exceptions are thrown
* verify any JNI or native code calls 
* find cases of unbounded memory allocations

Apache Commons Compress uses JNI for at least ZStd, so the fuzzing target
tries to trigger this and also any other unexpected exceptions and 
unbounded memory allocations.

# How to fuzz

Build the fuzzing target:

    ./gradlew shadowJar

Copy over the corpus of test-files from Apache Commons Compress sources

    cp -a /opt/commons-compress/src/test/resources corpus/

You can add documents from other testing-corpora as well. Valid documents
as well as slightly broken ones are good sources as this helps the fuzzer 
to come up with interesting new cases. 

Download Jazzer from the [releases page](https://github.com/CodeIntelligenceTesting/jazzer/releases), 
choose the latest version and select the file `jazzer-<os>-<version>.tar.gz`

Unpack the archive:

    tar xzf jazzer-*.tar.gz

Invoke the fuzzing:

    ./jazzer --cp=build/libs/compress-fuzz-all.jar --instrumentation_includes=org.apache.commons.** --target_class=org.dstadler.compress.fuzz.Fuzz -rss_limit_mb=4096 corpus

In this mode Jazzer will stop whenever it detects an unexpected exception 
or crashes.

You can use `--keep_going=10` to report a given number of exceptions before stopping.

See `./jazzer` for options which can control details of how Jazzer operates.

# License

Copyright 2021-2023 Dominik Stadler

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
