#!/bin/bash

DEBUG_FILE=/home/user/.debug_log

rm $DEBUG_FILE

while true
do
  nice -n 20 ./vuln_fast "localhost user"
done
