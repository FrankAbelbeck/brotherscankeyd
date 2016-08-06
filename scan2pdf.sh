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
# perform various sanity checks
#
if [ $# -eq 0 ]; then
	cat <<ENDOFMSG
Need at least one argument (SANE device address)!
usage: scan2pdf.sh SANEADDRESS [odd|even] [reversed]

       If "odd" or "even" is given, this script assumes it will scan odd or even
       pages; odd pages are saved as xyz-odd.pdf, even pages are merged with
       previously scanned odd pages.

       If "reversed" is given, this script assumes the scanned pages to be in
       reversed order (paper stack scanned back to front); this argument is
       only processd when both even and odd pages were scanned (prior to
       merging both) and can be used to simplify double-sided scanning (just
       flip stack and scan again).
ENDOFMSG
	exit 1
fi

if [ ! -e "/usr/bin/convert" ]; then
	echo "Could not find convert (part of imagemagick)!"
	exit 1
fi

if [ ! -e "/usr/bin/scanadf" ]; then
	echo "Could not find scanadf (part of sane-frontends)!"
	exit 1
fi

if [ ! -e "/usr/bin/pdftk" ]; then
	echo "Could not find pdftk!"
	exit 1
fi

#
# security precaution: change into tmp
#
pushd /tmp

#
# create unique filename from date and if necessary from an index
#
if [[ "$2" == "odd" || "$2" == "even" ]]; then
	SUFFIX="-$2" # insert "odd" or "even" into the filename
else
	SUFFIX=""
fi

BASEDIR="/mnt/data/Scan/"
BASENAME="$BASEDIR$(/bin/date +%Y-%m-%d)_scan"
FILENAME="$BASENAME$SUFFIX.pdf"
N=-1
while [ -e "$FILENAME" ]; do
	# filename already exists: increment counter, try again
	let "N++"
	FILENAME="$BASENAME$SUFFIX"_"$N".pdf
done

# perform the scan:
#  (1) create a temporary filename
#  (2) batch-scan using the ADF and scanadf
#  (3) convert all scanned images to one PDF
#  (4) remove images
IMGNAME="$(/usr/bin/mktemp -u)"

/usr/bin/scanadf --device-name="$1" --output-file="$IMGNAME-%02d" --mode="24bit Color[Fast]" --resolution="300" 2>&1
/usr/bin/convert "$IMGNAME*" -trim -compress jpeg -quality 92 -page A4 "$FILENAME"
# remove all scanned images
echo /bin/rm "$IMGNAME"*

#  (5) if either odd or even is set: merge with newest even or odd file
if [ -n "$SUFFIX" ]; then
	# either even or odd set: merge the latest odd/even files into a normal pdf;
	# if one of these files does not exist, this might be the first half of
	# duplex scanning, so do nothing.
	ODDFILE="$(/bin/ls -t1 "$BASEDIR"*-odd.pdf 2>/dev/null | head -1)" # get latest odd file, ignore errors
	EVENFILE="$(/bin/ls -t1 "$BASEDIR"*-even.pdf 2>/dev/null | head -1)" # get latest even file, ignore errors
	if [ -n "$ODDFILE" -a -n "$EVENFILE" ]; then
		# odd and even file found
		# create unique target name
		FILENAME="$BASENAME.pdf"
		N=-1
		while [ -e "$FILENAME" ]; do
			# filename already exists: increment counter, try again
			let "N++"
			FILENAME="$BASENAME"_$N.pdf
		done
		# shuffle odd and even into one document
		# take into account reversing the staple?
		if [[ "$3" == "reversed" ]]; then
			/usr/bin/pdftk A="$ODDFILE" B="$EVENFILE" shuffle A Bend-1 output "$FILENAME"
		else
			/usr/bin/pdftk A="$ODDFILE" B="$EVENFILE" shuffle A B output "$FILENAME"
		fi
		# remove odd and even file: now replaced by merged file
		echo /bin/rm "$EVENFILE"
		echo /bin/rm "$ODDFILE"
	fi
fi

# return from tmp
popd
