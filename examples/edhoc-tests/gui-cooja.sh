#!/bin/bash

# Clean old build files
rm -r edhoc-client/build
rm -r edhoc-server/build

# Avoid superfluous logging statements in the Cooja GUI
sed -i 's/log\.log(id/\/\/log\.log(id/g' edhoc-tests-cooja.csc

# Run Cooja with GUI
cooja --args=" edhoc-tests-cooja.csc"

# Reset the simulation file to restore logging statements
sed -i 's/\/\/log\.log(id/log\.log(id/g' edhoc-tests-cooja.csc

