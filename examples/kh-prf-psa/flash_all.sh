#!/bin/bash

declare -a StringArray=("L4100CUS")


for val in ${StringArray[@]}; do
  /bin/false
  while [ $? -ne 0 ]; do
    openocd -f $(pwd)/scripts/$val.cfg -c "program $(pwd)/device.simplelink verify reset exit"
  done
done
