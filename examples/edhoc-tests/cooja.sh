#!/bin/bash

# Remove old test log
rm COOJA.testlog

# Clean old build files
rm -r edhoc-client/build
rm -r edhoc-server/build

# Run Cooja with the specified arguments in no-GUI mode
cooja --args="--no-gui edhoc-tests-cooja.csc" && \
# After Cooja finishes, process the log file COOJA.testlog
cat COOJA.testlog | \
# Use sed to apply different colors to the lines
sed -e 's/^1.*/\x1b[38;2;200;200;255m&\x1b[0m/' \
    -e 's/^2.*/\x1b[38;2;200;255;200m&\x1b[0m/' \
    -e 's/^I.*/\x1b[31m&\x1b[0m/' \
    -e 's/^C.*/\x1b[32m&\x1b[0m/'

