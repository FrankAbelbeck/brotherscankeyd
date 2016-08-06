#!/bin/bash
# scan2image.sh: Scan Key Daemon scan-to-image script example
# Copyright (C) 2016 Frank Abelbeck <frank.abelbeck@googlemail.com>
#
# This file is part of the brotherscankeyd program "brotherscankeyd.py".
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>."""

#
# usage: scan2image.sh devicename [resolution]
#
if [ $# -eq 0 ]; then
	cat <<ENDOFMSG
Need at least one argument (SANE device address)!
usage: scan2image.sh SANEADDRESS [RESOLUTION]
       RESOLUTON defaults to 600 (dpi).
ENDOFMSG
	exit 1
fi

if [ ! -e "/usr/bin/scanimage" ]; then
	echo "Could not find scanimage (part of sane-backends)!"
	exit 1
fi

#
# create unique filename from date and if necessary from an index
#
DATE="$(/bin/date +%Y-%m-%d)"
FILENAME="/mnt/data/Scan/"$DATE"_scan.tiff"
N=-1
while [ -e $FILENAME ]; do
	# filename already exists: increment counter, try again
	let "N++"
	FILENAME="/mnt/data/Scan/"$DATE"_scan_$N.tiff"
done

if [ -n "$2" ]; then
	RESOLUTION="$2"
else
	RESOLUTION=600
fi

# perform the scan
#
# I/O redirection:
#  (1) redirect stderr to the target of stdout "2>&1"
#  (2) redirect stdout to the file $FILENAME
# result: stderr is printed to the stdout stream of the process,
#         stdout (the image data) is routed to the file
/usr/bin/scanimage --device-name="$1" --mode="24bit Color[Fast]" --resolution="$RESOLUTION" --source="FlatBed" 2>&1 1>"$FILENAME"
