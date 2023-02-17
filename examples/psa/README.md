# Guide

## Materials needed:
Two cc1352 simplelink boards.
Contiki-NG
Uniflash 5.2 or higher


**NOTE:** If you are unfamiliar with Contiki-NG, the documentation can be found here: [Contiki-NG documentation](https://docs.contiki-ng.org/en/develop/).
**NOTE:** Before flashing one device, turn of all other devices to make sure the correct device is being flashed.
**NOTE:** After flashing a Simplelink device it will only boot partialy. You need to Click the "Reset Button" (white component, next to the USB connector on the board).

## Steps:
### Build and flash Border Router
Make sure that 2.4GHz networking is enabled.
Build border router by moving to contiki-ng/examples/rpl-border-router
run 
`make`

Flash the file to one of the Simplelink boards. This board is refered to as BR from here on.


### Build and flash Client
Build the test client. In either contiki-ng/examples/psa/kh-prf-psa or contiki-ng/examples/psa/lass or contiki-ng/examples/psa/dipsauce
run
`make`

Flash the file to the other simplelink board. This board will be refered to as the Client from here on.

### Setup network
Turn on Client. This is to ensure Client is enumerated as /dev/ttyACM0
Click the "Reset Button" on Client.

Turn on BR. The BR will be enumerated as /dev/ttyACM2
Click the "Reset Button" on BR.

Start tunslip6 by moving to directory contiki-ng/tools/serial-io
Run:
`sudo ./tunslip6 -B 115200 -s /dev/ttyACM2 fd00::1/64`
**NOTE:** This assumes that the BR is enumerated as /dev/ttyACM2, otherwise this will not work!
**NOTE:** tunslip6 will print the "server address" this can be used to look on the neighbors and routes of the BR.

### Start experiments and write to file.
Run:
`minicom -D /dev/ttyACM0 -C log.txt`

* Start the test-server. This will be either kh-prf-psa-server.py, lass-server.py, or dipsauce-server.py. The servers are located in the respective contiki-ng/examples folders.
Run (for example):
python kh-prf-psa-server.py

* Reboot Client by clicking "Reset Button"
After the 60 second wait, the execution of the tests will start.
The tests will print CSV to minicom that is written to the file log.txt (the filename can of course be changed).


* After tests are completed.
Remove all lines from log.txt that does not contain CSV output from the tests.
Contiki-NG prints a lot of information on boot, remove that.
Then remember to add the correct first line "type,....". Refer to the dummy files in practical_psa_results/processing_time
Move the file to practical_psa_results/processing_time, and give it a better name. Remember to change the filename in the time.py script!

