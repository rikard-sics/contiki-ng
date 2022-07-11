#!/bin/bash

#declare -a StringArray=("L4100CUS" "L4100CUO"  "L4100CVP" "L4100AWK" )
#declare -a StringArray=("L4100CUS" "L4100CUO")
declare -a StringArray=("L4100CUO")


for val in ${StringArray[@]}; do
  /bin/false
  while [ $? -ne 0 ]; do
    openocd -f $(pwd)/scripts/$val.cfg -c "program $(pwd)/device.simplelink verify reset exit"
  done
done
