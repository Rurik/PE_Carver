# PE File Carver
# by Brian Baskin (@bbaskin)
# 
# Horrible code, I'm sure, but it works.
# I'm just a shadetree-programmer
# Don't like it? Pull it, make it better, and teach me.
#
# This program searches any large logical file for executable files, which are then 
# carved out and stored onto the hard drive.
# It searches for the text 'This program' which is found in nearly all executables.
# It then attempts to read the EXE header, find the file size, and extract that number
# of bytes out to save.
# It can be easily modified, in my opinion, for your needs.
#
# Version 1.0 - 18 Dec 12
#   Code I threw together because Foremost/Scalpel gave me so many false positives
# Version 1.1 - 27 Jun 16
#   OMG, 3.5 years later. Now it's a "legit" application that runs somewhat better
#
# ToDo: Add RAR SFX parsing. Already got it spec'ed out. Then all other overlays

import argparse
import bitstring   # Used to parse data. Download from: http://code.google.com/p/python-bitstring/
import os
import pefile      # Used to parse PE header. Download from: http://code.google.com/p/pefile/
import sys
from datetime import datetime

g_log = ''

def file_exists(fname):
    return os.path.exists(fname) and os.access(fname, os.R_OK)


def log(string):
# This just tees output to a file and stdout
    if g_log:
        try:
            open(g_log, 'a').write(string + '\n')
        except:
            pass


def getSize_FromPE(PE_data):
# Performs basic lookup to find the end of an EXE, based upon the
# size of PE sections. Same algorithm is used to find EXE overlay
# FYI: This will miss any overlay data, such as RAR SFX archives, etc
    try:
        pe = pefile.PE(data=PE_data)
        return pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
    except:
        return 0


def getArgs():
    global g_log

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Raw file to carve', required=True)
    parser.add_argument('-o', '--output', help='Output folder for extracted files', required=True)
    parser.add_argument('--log', help='Log output file', required=False)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.file and not file_exists(args.file):
        print '[!] Source file not found: {}'.format(args.file)
        sys.exit(1)
    if args.log:
        g_log = args.log

    return args


def main():
    args = getArgs()

    time = datetime.now().strftime('[%d %b %y @ %H:%M:%S]')
    log('Scan started on %s at %s' % (args.file, time))
    entries = []
    fstream = bitstring.ConstBitStream(filename = args.file)
    results = fstream.findall(b'0x546869732070726F6772616D')  # 'This program'
    log('Gathering search hits...')
    for i in results:
        # The result offsets are stored as binary values, so you have to divide by 8
        # -78 is the negative offset to the beginning of 'MZ' from 'This program'
        hit = int(i)/8-78
        entries.append(hit)


    log('Parsing EXEs...')
    ifile = open(args.file, 'rb')
    for hit in entries:
        ifile.seek(hit)
        PE_header = ifile.read(1024)
        pesize = getSize_FromPE(PE_header)
        
        # These sizes are arbitrary. Had numerous junk PE headers (>30GB), so did base limiting
        if (10000 < pesize < 2000000) and PE_header[0:2] == 'MZ':
            log('Found at: 0x%X (%d bytes)' % (hit, pesize))
            ifile.seek(hit)
            PE_data = ifile.read(pesize)
            outfile = '%s_%X.livebin' % (args.file.split('\\')[-1], hit)
            open(outfile, 'wb').write(PE_data)
        else:
            log('Ignored PE header at 0x%X' % hit)
        
    time = datetime.now().strftime('[%d %b %y @ %H:%M:%S]')
    log('Scan ended on %s at %s' % (args.file, time))

if __name__ == '__main__':
    main()