#!/bin/bash

#
# create unique filename from date and if necessary from an index
#
DATE="$(/bin/date +%Y-%m-%d)"
FILENAME="/tmp/"$DATE"_scan.tiff"
N=-1
echo $FILENAME
while [ -e $FILENAME ]; do
	let "N++"
	FILENAME="/tmp/"$DATE"_scan_$N.tiff"
	echo $FILENAME
done
#
# perform the scan
#
# I/O redirection:
#  (1) redirect stderr to the target of stdout "2>&1"
#  (2) redirect stdout to the file $FILENAME
# result: stderr is printed to the processes stdout stream,
#         stdout (the image data) is routed to the file
#
/usr/bin/scanimage --device-name "$1" --mode "24bit Color [Fast]" --resolution 600 --source FlatBed 2>&1 1>$FILENAME
