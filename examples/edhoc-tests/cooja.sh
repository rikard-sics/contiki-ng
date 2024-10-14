#!/bin/bash

# Remove old test log
rm COOJA.testlog
rm COOJA2.testlog
rm COOJA-m0.testlog
rm COOJA-m3.testlog

# Clean old build files
rm -r edhoc-client/build
rm -r edhoc-server/build

# Run Cooja with the specified arguments in no-GUI mode (using Method 0)
cooja --args="--no-gui edhoc-tests-cooja.csc" && \
# After Cooja finishes, process the log file COOJA.testlog
cat COOJA.testlog | \
# Use sed to apply different colors to the lines
sed -e 's/^1.*/\x1b[38;2;200;200;255m&\x1b[0m/' \
    -e 's/^2.*/\x1b[38;2;200;255;200m&\x1b[0m/' \
    -e 's/^I.*/\x1b[31m&\x1b[0m/' \
    -e 's/^C.*/\x1b[32m&\x1b[0m/'
mv COOJA.testlog COOJA-m0.testlog

# Check if the log file exists
file_to_check="COOJA-m0.testlog"
if [ ! -f "$file_to_check" ]; then
  echo "Error: File $file_to_check does not exist."
  echo "Stopping further execution."
  exit 1
fi

# Search for the string "TEST FAILED" in the log file
if grep -q "TEST FAILED" "$file_to_check"; then
  echo "Error: Test failed found in $file_to_check"
  echo "Stopping further execution."
  exit 1
fi

# Check if the string "TEST OK" exists in the log file (if not fail)
if ! grep -q "TEST OK" "$file_to_check"; then
  echo "Error: 'TEST OK' not found in $file_to_check"
  echo "Stopping further execution."
  exit 1
fi


# Run Cooja with the specified arguments in no-GUI mode (using Method 3)
sed -i 's/#define METHOD METH0/#define METHOD METH3/g' /home/user/contiki-ng/os/net/security/edhoc/edhoc-config.h
cooja --args="--no-gui edhoc-tests-cooja.csc" && \
# After Cooja finishes, process the log file COOJA.testlog
cat COOJA.testlog | \
# Use sed to apply different colors to the lines
sed -e 's/^1.*/\x1b[38;2;200;200;255m&\x1b[0m/' \
    -e 's/^2.*/\x1b[38;2;200;255;200m&\x1b[0m/' \
    -e 's/^I.*/\x1b[31m&\x1b[0m/' \
    -e 's/^C.*/\x1b[32m&\x1b[0m/'
sed -i 's/#define METHOD METH3/#define METHOD METH0/g' /home/user/contiki-ng/os/net/security/edhoc/edhoc-config.h
mv COOJA.testlog COOJA-m3.testlog

# Check if the log file exists
file_to_check="COOJA-m3.testlog"
if [ ! -f "$file_to_check" ]; then
  echo "Error: File $file_to_check does not exist."
  echo "Stopping further execution."
  exit 1
fi

# Search for the string "TEST FAILED" in the log file
if grep -q "TEST FAILED" "$file_to_check"; then
  echo "Error: Test failed found in $file_to_check"
  echo "Stopping further execution."
  exit 1
fi

# Check if the string "TEST OK" exists in the log file (if not fail)
if ! grep -q "TEST OK" "$file_to_check"; then
  echo "Error: 'TEST OK' not found in $file_to_check"
  echo "Stopping further execution."
  exit 1
fi

