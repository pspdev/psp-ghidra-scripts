#Resolve Sony PSP NIDs to function names
#@author John Kelley <john@kelley.ca>
#@category Analysis
#@website https://github.com/pspdev/psp-ghidra-scripts

# PPSSPP NIDs: sift -e "\{(0[Xx][0-9A-F]+),\s+[^,]*,\s+\"[a-zA-Z0-9]+\"," | awk '{print $2 " " $4}'|tr -d "{,\""

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ghidra.program.model.data import DataTypeConflictHandler, ArrayDataType
from ghidra.app.cmd.function import DeleteFunctionCmd
from ghidra.app.util.cparser.C import CParser
from ghidra.app.util.opinion import ElfLoader
from ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Utilities import *
from ghidra.program.model.data import TerminatedStringDataType
import xml.etree.ElementTree as ET
import os.path
import sys
import re

def getNameForNID(nidDB, lib_name, nid):
    return nidDB.get(nid, lib_name+"_"+nid)

def createPSPModuleInfoStruct():
    # struct from prxtypes.h
    PSPModuleInfo_txt = """
    struct PspModuleInfo {
        unsigned int flags;
        char name[28];
        void *gp;
        void *exports;
        void *exp_end;
        void *imports;
        void *imp_end;
    };"""

    # Get Data Type Manager
    data_type_manager = currentProgram.getDataTypeManager()

    # Create CParser
    parser = CParser(data_type_manager)

    # Parse structure
    parsed_datatype = parser.parse(PSPModuleInfo_txt)

    # Add parsed type to data type manager
    datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)

    # datatype isn't accurate, so lets request it from data type manager and return it
    return currentProgram.getDataTypeManager().getDataType("/PspModuleInfo")

def createPSPModuleImportStruct():
    # struct from prxtypes.h
    PspModuleImport_txt = """
    struct PspModuleImport{
        char *name;
        unsigned int flags;
        byte     entry_size;
        byte     var_count;
        unsigned short func_count;
        unsigned int *nids;
        unsigned int *funcs;
    };"""

    # Get Data Type Manager
    data_type_manager = currentProgram.getDataTypeManager()

    # Create CParser
    parser = CParser(data_type_manager)

    # Parse structure
    parsed_datatype = parser.parse(PspModuleImport_txt)

    # Add parsed type to data type manager
    datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)

    # datatype isn't accurate, so lets request it from data type manager and return it
    return currentProgram.getDataTypeManager().getDataType("/PspModuleImport")

def createPSPModuleExportStruct():
    # struct from prxtypes.h
    PSPModuleExport_txt = """
    struct PspModuleExport
    {
        char *name;
        unsigned int flags;
        byte     entry_len;
        byte     var_count;
        unsigned short func_count;
        unsigned int *exports;
    };"""

    # Get Data Type Manager
    data_type_manager = currentProgram.getDataTypeManager()

    # Create CParser
    parser = CParser(data_type_manager)

    # Parse structure
    parsed_datatype = parser.parse(PSPModuleExport_txt)

    # Add parsed type to data type manager
    datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)

    # datatype isn't accurate, so lets request it from data type manager and return it
    return currentProgram.getDataTypeManager().getDataType("/PspModuleExport")

def resolveExports(exports_addr, exports_end, nidDB, moduleInfo_name):
    # undefine .lib.stub section members
    currentProgram.getListing().clearCodeUnits(exports_addr, exports_end, False)

    export_t = createPSPModuleExportStruct()
    export_t_len = export_t.getLength()
    num_exports = exports_end.subtract(exports_addr)/export_t_len
    if num_exports < 1:
        print "No exports to resolve"
        return 0

    exports_offset = 0
    addr = exports_addr
    modules = []
    while addr.add(export_t_len).compareTo(exports_end) <= 0:
        # create struct at address
        currentProgram.getListing().createData(addr, export_t, export_t_len)
        # create module object from data
        module = getDataAt(addr)
        # append module to modules list
        modules.append(module)
        # get entry len & update exports_offset
        entry_len = module.getComponent(2).value.getUnsignedValue()
        exports_offset += 4*entry_len
        # update address
        addr = exports_addr.add(exports_offset)

        
    # iterate through array of exports
    module_index = 0
    for module in modules:
        # roundabout way to grab the string pointed to by the name field
        module_name_addr = module.getComponent(0)
        module_name = "(none)"
        # why we can't just get a number to compare against 0 is beyond me
        if module_name_addr.value.toString() != "00000000":
            module_name = getDataAt(module_name_addr.value).value
        elif module_index == 0:
            module_name = moduleInfo_name
        else:
            module_name = "unknown"
        # increase module count
        module_index += 1

        # another roundabout way to get an actual number
        num_vars  = module.getComponent(3).value.getUnsignedValue()
        num_funcs = module.getComponent(4).value.getUnsignedValue()
        nids_base = module.getComponent(5).value
        num_nids = num_vars + num_funcs
        stub_base = nids_base.add(4 * num_nids)
        # at stub_base, function NIDs come first, followed by variable NIDs
        #print module_name,"has", num_vars, "variables, and", num_funcs, "exported functions"
        # convert raw data to DWORDs to 'show' NIDs
        createDwords(nids_base, num_nids)
        # convert raw data to pointers for vars & funcs
        for n in range(num_nids):
           createPointer(currentProgram, stub_base.add(4 * n))
        # label the NIDs with the module name
        createLabel(nids_base, module_name+"_nids", True)
        # label the funcs with the module name
        createLabel(stub_base, module_name+"_funcs", True)
        # label the vars with the module name
        if num_vars > 0:
            createLabel(stub_base.add(4*num_funcs), module_name+"_vars", True)

        print "Resolving Export NIDs for",module_name
        for func_idx in range(num_funcs):
            nid_addr = nids_base.add(4 * func_idx)
            stub_addr = getDataAt(stub_base.add(4 * func_idx)).value
            # get NID hex and convert to uppercase
            nid = str(getDataAt(nid_addr).value).upper()
            # ensure 0x instead of 0X
            nid = nid.replace('X', 'x')
            # resolve NID to function name
            label = getNameForNID(nidDB, module_name, nid)
            # delete any existing function so we can re-name it
            df = DeleteFunctionCmd(stub_addr, True)
            df.applyTo(currentProgram)
            # create a function with the proper name
            createFunction(stub_addr, label)

        for var_idx in range(num_vars):
            nid_addr = nids_base.add(4*num_funcs + 4*var_idx)
            stub_addr = getDataAt(stub_base.add(4*num_funcs + 4*var_idx)).value
            # get NID hex and convert to uppercase
            nid = str(getDataAt(nid_addr).value).upper()
            # ensure 0x instead of 0X
            nid = nid.replace('X', 'x')
            # resolve NID to variable name
            label = getNameForNID(nidDB, module_name, nid)
            createLabel(stub_addr, "var_"+label, True)

def resolveImports(imports_addr, imports_end, nidDB):
    # undefine .lib.stub section members
    currentProgram.getListing().clearCodeUnits(imports_addr, imports_end, False)

    # create array of PspModuleImport
    import_t = createPSPModuleImportStruct()
    import_t_len = import_t.getLength()
    num_imports = imports_end.subtract(imports_addr)/import_t_len
    if num_imports < 1:
        print "No imports to resolve"
        return 0

    imports_offset = 0
    addr = imports_addr
    modules = []
    while addr.add(import_t_len).compareTo(imports_end) <= 0:
        # create struct at address
        currentProgram.getListing().createData(addr, import_t, import_t_len)
        # create module object from data
        module = getDataAt(addr)
        # append module to modules list
        modules.append(module)
        # get entry len & update exports_offset
        entry_len = module.getComponent(2).value.getUnsignedValue()
        imports_offset += 4 * entry_len
        # update address
        addr = imports_addr.add(imports_offset)

    # iterate through array of library imports
    for module in modules:
        # validate name field, thanks to FW 6.61 wlan.prx (See Issue #1)
        module_name_ptr = module.getComponent(0).value
        module_name_data = getDataAt(module_name_ptr)
        if module_name_data is None:
            print "WARNING: Attempting to correct incomplete string datatype for PSPModuleImport.name"
            try:
                currentProgram.getListing().createData(module_name_ptr, TerminatedStringDataType.dataType)
            except ghidra.program.model.util.CodeUnitInsertionException as e:
                # this is brittle but we lack a better way right now
                # fingers crossed that Ghidra doesn't change their python exception message
                match = re.match(".*([0-8A-Fa-f]{8})\sto\s([0-8A-Fa-f]{8})", e.message)
                if match:
                    print "WARNING: Clearing data from ", match.group(1), "to", match.group(2)
                    currentProgram.getListing().clearCodeUnits(module_name_ptr.getNewAddress(int("0x"+match.group(1), 16)), module_name_ptr.getNewAddress(int("0x"+match.group(2), 16)), False)
                    currentProgram.getListing().createData(module_name_ptr, TerminatedStringDataType.dataType)

        # roundabout way to grab the string pointed to by the name field
        module_name = getDataAt(module.getComponent(0).value).value
        # another roundabout way to get an actual number
        # num_vars  = module.getComponent(3).value.getUnsignedValue()
        num_funcs = module.getComponent(4).value.getUnsignedValue()
        nids_base = module.getComponent(5).value
        stub_base = module.getComponent(6).value
        # TODO: account for variables here, like above.
        #       We have yet to see variables in an import
        # num_nids = num_vars + num_funcs
        # convert raw data to DWORDs to 'show' NIDs
        createDwords(nids_base, num_funcs)
        # label the NIDs with the module name
        createLabel(nids_base, module_name+"_nids", True)

        print "Resolving Import NIDs for",module_name
        for func_idx in range(num_funcs):
            nid_addr = nids_base.add(4*func_idx)
            stub_addr = stub_base.add(8*func_idx) # should this be 4?
            # get NID hex and convert to uppercase
            nid = str(getDataAt(nid_addr).value).upper()
            # ensure 0x instead of 0X
            nid = nid.replace('X', 'x')
            # resolve NID to function name
            label = getNameForNID(nidDB, module_name, nid)
            # delete any existing function so we can re-name it
            df = DeleteFunctionCmd(stub_addr, True)
            df.applyTo(currentProgram)
            # create a function with the proper name
            createFunction(stub_addr, label)

# .lib.stub isn't required in PRXes, so use .rodata.sceModuleInfo instead. Just kidding, this isn't
# guaranteed to exist either - I'm looking at you, Assassin's Creed - Bloodlines. Instead,
# calculate the address by examining the first load command in _elfProgramHeaders and subtracting
# p_offset from p_paddr
loadcmds = getDataAt(currentProgram.getMemory().getBlock("_elfProgramHeaders").getStart())
# get first load command
loadcmd = loadcmds.getComponent(0)
# 2nd component is p_offset
load_offset = loadcmd.getComponent(1).getValue().getValue() # Data->Scalar->Long
# 4th component is p_addr
load_paddr = loadcmd.getComponent(3).getValue()

# account for kernel mode PRX with upper bit set
if load_paddr.value & 0x80000000:
    load_paddr = load_paddr.subtract(0x80000000)

sceModuleInfo_addr = getAddressFactory().getAddress(load_paddr.subtract(load_offset).toString())
# get the ELF's image base since PRX's aren't based at 0
image_base = ElfLoader.getElfOriginalImageBase(currentProgram)
sceModuleInfo_addr = sceModuleInfo_addr.add(image_base)

# (re-)create sceModuleInfo struct
sceModuleInfo_t = createPSPModuleInfoStruct()
sceModuleInfo_t_len = sceModuleInfo_t.getLength()
currentProgram.getListing().clearCodeUnits(sceModuleInfo_addr, sceModuleInfo_addr.add(sceModuleInfo_t_len), False)
currentProgram.getListing().createData(sceModuleInfo_addr, sceModuleInfo_t)
sceModuleInfo = getDataAt(sceModuleInfo_addr)
# 4th component is ptr to exports
exports_addr = sceModuleInfo.getComponent(3).getValue()
# 5th component is exports end
exports_end = sceModuleInfo.getComponent(4).getValue()
# 6th component is ptr to stubs, aka 'imports'
imports_addr = sceModuleInfo.getComponent(5).getValue()
# 7th component is stubs end
imports_end = sceModuleInfo.getComponent(6).getValue()

# Ghidra hack to get the current directory to load data files
script_path = os.path.dirname(getSourceFile().getCanonicalPath())

# load NID database
xml_root = ET.parse(os.path.join(script_path, "ppsspp_niddb.xml"))

# construct dict of NID->NAME to greatly speed up lookup
nidDB = {}
funcs = xml_root.findall(".//FUNCTION")
for func in funcs:
    nid = func.find("NID").text
    name = func.find("NAME").text
    nidDB[nid] = name

# resolve all the NIDs!
resolveExports(exports_addr, exports_end, nidDB, sceModuleInfo.getComponent(1).value)
resolveImports(imports_addr, imports_end, nidDB)

