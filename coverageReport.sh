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


# extract class-files of Apache POi
mkdir -p build/compressfiles
cd build/compressfiles
for i in `find /opt/apache/commons-compress/dist/binaries/ -name *.zip`; do
  echo $i
  unzip -o -q $i
done


# Remove some packages that we do not want to include in the Report
#rm -r com
#rm -r org/openxmlformats
#rm -r org/etsi
#rm -r org/w3

cd -


# Finally create the JaCoCo report
java -jar /opt/poi/lib/util/jacococli.jar report build/jacoco/test.exec \
 --classfiles build/compressfiles \
 --sourcefiles /opt/apache/commons-compress/dist/source \
 --html build/reports/jacoco


echo All Done, report is at build/reports/jacoco/index.html