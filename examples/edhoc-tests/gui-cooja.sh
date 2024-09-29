sed -i 's/log\.log(id/\/\/log\.log(id/g' edhoc-tests-cooja.csc
cooja --args=" edhoc-tests-cooja.csc"
sed -i 's/\/\/log\.log(id/log\.log(id/g' edhoc-tests-cooja.csc

