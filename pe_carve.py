import sys, bitstring, pefile
from datetime import datetime

def log(string):
# This just tees output to a file and stdout
    print string
    open('exe_scan.log', 'a').write(string + "\r\n")

def getSize_FromPE(PE_data):
# Performs basic lookup to find the end of an EXE, based upon the
# size of PE sections. Same algorithm is used to find EXE overlay
    try:
        pe = pefile.PE(data=PE_data)
        return pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
    except:
        return 0
    
# Start main
try:
    fname = sys.argv[1]
except:
    print "ERROR: Provide filename to parse."
    quit

time = datetime.now().strftime("[%d %b %y @ %H:%M:%S]")
log('Scan started on %s at %s' % (fname, time))
list = []
z = bitstring.ConstBitStream(filename = fname)
results = z.findall(b'0x546869732070726F6772616D')  # "This program"
log( "Gathering search hits...")
for i in results:
    # -78 is the negative offset to the beginning of "MZ" from "This program"
    hit = int(i)/8-78
    list.append(hit)
log( "Parsing EXEs...")
ifile = open(fname, 'rb')
for hit in list:
    ifile.seek(hit)
    PE_header = ifile.read(1024)
    pesize = getSize_FromPE(PE_header)
    
    # These sizes are arbitrary. Had numerous junk PE headers (>30GB), so did base limiting
    if 10000 < pesize < 10000000:
        log( "Found at: 0x%X (%d bytes)" % (hit, pesize))
        ifile.seek(hit)
        PE_data = ifile.read(pesize)
        outfile = "%s_%X.livebin" % (fname.split("\\")[-1], hit)
        open(outfile, 'wb').write(PE_data)
    else:
        log ("Ignored PE header at 0x%X" % hit)
    
time = datetime.now().strftime("[%d %b %y @ %H:%M:%S]")
log( 'Scan ended on %s at %s' % (fname, time))
