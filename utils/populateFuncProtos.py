#!/bin/env python2
import xml.etree.ElementTree as ET
import os.path
import sys
import re
import subprocess

# load NID database
xml_root = ET.parse("ppsspp_niddb.xml")

funcs = xml_root.findall(".//FUNCTION")
for func in funcs:
    name = func.find("NAME").text
    # parse function prototype vars
    ret_type = func.find("RETURN_TYPE")
    args = func.find("ARGS")
    if ret_type is None or args is None:
        
        res = subprocess.Popen(['sift', '--no-filename', '-xh', " "+name+"\(", 'pspsdk/src/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = res.communicate()
        if stdout is not None and len(stdout) > 1:
            print "Got proto for", name,":",
            output = stdout.replace(name+"(", "(").replace(");","")
            stuff = output.split("(")
            if len(stuff) == 2:
                ret_type = stuff[0].strip()
                raw_args = stuff[1].split(",")
                args = []
                for arg in raw_args:
                    args.append(arg.strip())
                print "ret:",ret_type,"args:",args
                ret_elem = ET.SubElement(func,"RETURN_TYPE")
                ret_elem.text = ret_type
                args_elem = ET.SubElement(func, "ARGS")
                for arg in args:
                    elem = ET.SubElement(args_elem, "ARG")
                    elem.text = arg
xml_root.write("new.xml")
