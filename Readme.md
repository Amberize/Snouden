App description
===============

Snouden is the char device driver that XORs input data and generates md5 for input and output strings.

Build and run string
====================

`make clean`

`make`

`insmod snouden`

`echo "Hey fool"` //or whatever you want

`cat /dev/snouden0`

`gmesg //for md5 output`

`rmmod snouden`

Repeat!

From author
===========

The app was written in honor of Edward Snowden.

It was the best I could make.

Nothing is true everything is permitted.
