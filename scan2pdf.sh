#!/bin/bash
#
# usage: scan2pdf.sh device name [odd|even]
#
DEVICE="$1"

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
