# mistrust-in-the-machine

## Description
You have to be careful with what code you execute locally. Sometimes though it is the code that is picky on where it wants to be executed. Run this on a suitably trusted machine and it will simply give you the flag.

In the patch folder you find a patch you can run to change the flag and machine the ELF binary will accept.

The provided ELF binary accepts both MAC adresses 00:06:14:4E:53:41 and 4E:53:41:00:06:14

## hint (1)
The ELF binary checks yor MAC address

## hint (2)
The challenge uses a slightly modified rc4

## hint (3)
The challenge titel can be abbreviated tot MitM, which also stands for Man-in-the-Middle. The crypto algorithm used splits a 48-bit key into two halves and you can use a MitM attack which effectively halves the used keysize 

