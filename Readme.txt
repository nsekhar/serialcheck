 Simple serial tester
~~~~~~~~~~~~~~~~~~~~~~
Usage:
- Create a random file.
  dd if=/dev/urandom of=binary count=1 bs=4096

- Copy the random file to both nodes.

- Start the test
  receiving node:
  	serialcheck -d /dev/ttyS0 -f binary -m r -l 10

  sending node:
  	serialcheck -d /dev/ttyUSB0 -f binary -m t -l 10

  Start the receiving side before the sending side. This will transfer
  the "binary" file 10 times and the other side will expect the file 10
  times.
  Once the program completes both sides should write something similar
  to

|  Needed 0 reads 1 writes loops 10 / 10
|  cts: 0 dsr: 0 rng: 0 dcd: 0 rx: 0 tx: 40960 frame 0 ovr 0 par: 0 brk: 0 buf_ovrr: 0

Problems:
~~~~~~~~~
- c

Problems:
~~~~~~~~~
- Option -m d for duplex does not work
  It sends data before the receiver is ready. As a workaround invoke it
  twice (r and t mode).

- The sender does not notice that it is no longer synchronized.
