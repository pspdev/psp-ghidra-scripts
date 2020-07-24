#!/bin/env python3

from pathlib import Path
import os
import sys

def removeComments(line):
    multiFound = False
    skip = False

    # parse out comments
    commentPos = line.rfind("//")
    if commentPos != -1:
        line = line[:commentPos]
    commentPos = line.rfind("/*")
    if commentPos != -1:
        multiFound = True
        begin = line[:commentPos]
        end = ""
        closingPos = line.find("*/", commentPos)
        if closingPos != -1:
            #print("Found */ in",line)
            end = line[closingPos+2:]
        else:
            skip = True
        line = begin + end
        #print("line now", line)
    line = line.strip()
    if multiFound and len(line) > 0:
        return removeComments(line)
    return (skip, line)

# parse these headers first as Ghidra requires pre-requisites to come first
pre_headers1 = Path('pspsdk').rglob('psptypes.h')
pre_headers2 = Path('pspsdk').rglob('pspkerneltypes.h')
pre_headers3 = Path('pspsdk').rglob('pspgu.h')
all_headers = Path('pspsdk').rglob('*.h')
headers = []
for header in pre_headers1:
    headers.append(header)
    
for header in pre_headers2:
    headers.append(header)

for header in pre_headers3:
    headers.append(header)

for header in all_headers:
    if header not in headers:
        headers.append(header)

for header in headers:
    #print("Processing",header)
    bannerDone = False
    with open(header, 'r') as fh:
        skip = False
        captureStruct = False
        structBuf = ""
        for line in fh.readlines():
            line = line.strip()
            if skip:
                # we're in a multi-line comment
                closingPos = line.find("*/")
                if closingPos != -1:
                    line = line[closingPos+2:]
                    skip = False
                else:
                    continue
            (skip, line) = removeComments(line)
            if len(line) == 0:
                continue

            if captureStruct:
                endPos = line.find("}")
                if endPos != -1:
                    line = structBuf + line + "\n"
                    structBuf = ""
                    captureStruct = False
                else:
                    structBuf += "\t" + line + "\n"
                    continue
            else:
                structPos = line.find("typedef struct")
                if structPos == -1:
                    structPos = line.find("struct")
                unionPos = line.find("typedef union")
                if (structPos != -1 or unionPos != -1) and line.rfind(";") == -1:
                    #account for single line typsedef struct
                    captureStruct = True
                    structBuf = line + "\n"
                    continue
                typedefPos = line.find("typedef")
                if typedefPos == -1:
                    continue
                if line.find("typedef enum") != -1:
                    continue
            if not bannerDone:
                print("\n//", os.path.basename(header))
                bannerDone = True
            print(line)