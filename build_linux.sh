#!/bin/bash

# https://www.hex-rays.com/wp-content/uploads/2019/12/pin_tutorial.pdf

make TARGET=ia32 || exit 1
rm -f idadbg.so
mv obj-ia32/idadbg.so .
rm obj-ia32/idadbg.o
rmdir rm obj-ia32

make TARGET=intel64 || exit 1
rm -f idadbg64.so
mv obj-intel64/idadbg64.so .
rm obj-intel64/idadbg.o
rmdir obj-intel64
