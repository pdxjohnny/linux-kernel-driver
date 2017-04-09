#!/bin/bash
MODULE=pewpew

rmmod ${MODULE}
rm -f /dev/${MODULE}0

insmod ${MODULE}.ko
MAJOR=$(grep $MODULE /proc/devices | awk '{print $1}')

if [[ "$MAJOR" == "" ]]; then
  echo "Failed to find major number of $MODULE"
  exit 1
fi

mknod /dev/${MODULE}0 c $MAJOR 0
chmod 666 /dev/${MODULE}0
