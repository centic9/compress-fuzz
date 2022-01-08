#!/bin/sh
#
#
# Small helper script to produce a coverage report when executing the fuzz-model
# against the current corpus.
#
# You need to enable the test in class CorpusCoverageTest
#

set -eu


# Remove any previous execution and make sure testing is triggered fully
./gradlew clean


# Execute the test with JaCoCo enabled
./gradlew check


# Fetch jar-dependencies
./gradlew getDeps


# extract jar-files of Apache Commons Compress
mkdir -p build/compressfiles
cd build/compressfiles

# then unpack the class-files
for i in `find ../runtime -name commons-compress-*.jar`; do
  echo $i
  unzip -o -q $i
done

cd -


# Finally create the JaCoCo report
java -jar /opt/poi/lib/util/jacococli.jar report build/jacoco/test.exec \
 --classfiles build/compressfiles \
 --sourcefiles /opt/apache/commons-compress/dist/source \
 --html build/reports/jacoco


echo All Done, report is at build/reports/jacoco/index.html
