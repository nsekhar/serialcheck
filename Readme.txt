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

and in error case the receive side:

Needed 20 reads 0 writes Oh oh, inconsistency at pos 2273 (0x8e1).
Original sample:
000008b0: 28 b2 18 c9 ec b5 2c b3  3a a1 29 b1 fc 27 20 7f   (.....,.:.)..' .
000008c0: 42 f8 d5 cb d8 52 ec b5  c8 76 d3 4b d2 57 44 6a   B....R...v.K.WDj
000008d0: 40 81 6a 82 27 fd 8d 50  84 70 bc 24 6b 3d 88 fd   @.j.'..P.p.$k=..
000008e0: 9f ac 78 a4 76 9b f9 1c  74 2c d6 79 22 60 c5 de   ..x.v...t,.y"`..
000008f0: 02 9c fb 52 21 4b 40 6f  80 69 2e 80 df 12 ba a0   ...R!K@o.i......
00000900: 75 57 d5 22 33 c0 f3 bc  94 f8 aa 22 9d 02 59 20   uW."3......"..Y 

Received sample:
000008b0: 28 b2 18 c9 ec b5 2c b3  3a a1 29 b1 fc 27 20 7f   (.....,.:.)..' .
000008c0: 42 f8 d5 cb d8 52 ec b5  c8 76 d3 4b d2 57 44 6a   B....R...v.K.WDj
000008d0: 40 81 6a 82 27 fd 8d 50  84 70 bc 24 6b 3d 88 fd   @.j.'..P.p.$k=..
000008e0: 9f 00 ac 78 a4 76 9b f9  1c 74 2c d6 79 22 60 c5   ...x.v...t,.y"`.
000008f0: de 02 9c fb 52 21 4b 40  6f 80 69 2e 80 df 12 ba   ....R!K@o.i.....
00000900: a0 75 57 d5 22 33 c0 f3  bc 94 f8 aa 22 9d 02 59   .uW."3......"..Y
loops 54878 / 4294967295

cts: 0 dsr: 0 rng: 0 dcd: 0 rx: 224792017 tx: 223379456 frame 0 ovr 1 par: 0 brk: 0 buf_ovrr: 0


Problems:
~~~~~~~~~
- Option -m d for duplex does not work
  It sends data before the receiver is ready. As a workaround invoke it
  twice (r and t mode).

- The sender does not notice that it is no longer synchronized.
