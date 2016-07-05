#!/bin/bash
# scan2pdf.sh: Scan Key Daemon scan-to-PDF script example
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
# usage: scan2pdf.sh devicename [odd|even] [reversed]
#
if [ $# -eq 0 ]; then
	exit 1
fi

#
# create unique filename from date and if necessary from an index
#
if [ "$2" == "odd" -o "$2" == "even" ]; then
	SUFFIX="-$2" # insert "odd" or "even" into the filename
else
	SUFFIX=""
fi

BASENAME="/tmp/$(/bin/date +%Y-%m-%d)_scan"
FILENAME="$BASENAME$SUFFIX.pdf"
N=-1
while [ -e $FILENAME ]; do
	# filename already exists: increment counter, try again
	let "N++"
	FILENAME="/tmp/"$BASENAME$SUFFIX"_$N.pdf"
done

# perform the scan:
#  (1) create a temporary filename
#  (2) batch-scan using the ADF
#  (3) convert all scanned images to one PDF
#  (4) remove images
IMGNAME="$(/usr/bin/mktemp -u)"
/usr/bin/scanimage --device-name "$1" --batch "$IMGNAME-%02d" --mode Color --resolution 300 --source ADF 2>&1
/usr/bin/convert $IMGNAME* --compress jpeg --quality 92 $FILENAME
/bin/rm $IMGNAME*

#  (5) if either odd or even is set: merge with newest even or odd file
if [ -n "$SUFFIX" ]; then
	# either even or odd set: merge the latest odd/even files into a normal pdf;
	# if one of these files does not exist, this might be the first half of
	# duplex scanning, so do nothing.
	ODDFILE="$(/bin/ls -t1 $BASENAME-odd* 2>/dev/null | head -1)" # get latest odd file, ignore errors
	EVENFILE="$(/bin/ls -t1 $BASENAME-even* 2>/dev/null | head -1)" # get latest even file, ignore errors
	if [ -n "$ODDFILE" -a -n "$EVENFILE" ]; then
		# odd and even file found
		# create unique target name
		BASENAME="/tmp/$(/bin/date +%Y-%m-%d)_scan"
		FILENAME="$BASENAME.pdf"
		N=-1
		while [ -e $FILENAME ]; do
			# filename already exists: increment counter, try again
			let "N++"
			FILENAME="/tmp/"$BASENAME"_$N.pdf"
		done
		# shuffle odd and even into one document
		# take into account reversing the staple?
		if [ "$3" == "reversed" ]; then
			/usr/bin/pdftk A="$ODDFILE" B="$EVENFILE" shuffle A Bend-1 output "$FILENAME"
		else
			/usr/bin/pdftk A="$ODDFILE" B="$EVENFILE" shuffle A B output "$FILENAME"
		fi
		# remove odd and even file: now replaced by merged file
		/bin/rm $EVENFILE*
		/bin/rm $ODDFILE*
	fi
fi
