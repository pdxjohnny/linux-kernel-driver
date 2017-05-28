#!/bin/bash
MODULE=pewpew

echo 0000:03:00.0 | tee /sys/module/e1000e/drivers/pci\:e1000e/unbind

rmmod ${MODULE}
rm -f /dev/${MODULE}0

insmod ${MODULE}.ko $*
MAJOR=$(grep $MODULE /proc/devices | awk '{print $1}')

if [[ "$MAJOR" == "" ]]; then
  echo "Failed to find major number of $MODULE"
  exit 1
fi

mknod /dev/${MODULE}0 c $MAJOR 0
chmod 666 /dev/${MODULE}0
