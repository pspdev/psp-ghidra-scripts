#Resolve Sony PSP NIDs to function names
#@author John Kelley <john@kelley.ca>
#@category Analysis
#@website https://github.com/pspdev/psp-ghidra-scripts

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
import xml.etree.ElementTree as ET
import os.path

def getFuncNameFromLibAndNID(xml_root, lib_name, nid):
	# fix for NIDs with leading 0's
	while len(nid) < 10:
		nid = nid[:2] + '0' + nid[2:]

	lib = xml_root.find(".//LIBRARY[NAME='"+lib_name+"']")
	if lib is not None:
		func = lib.find(".//FUNCTION[NID='"+nid+"']")
		if func is not None:
			return func.find("NAME").text
	print "WARN: NID "+nid+" in "+lib_name+" not documented"
	return lib_name+"_"+nid

def createPSPModuleImportStruct():
	# struct from prxtypes.h
	PspModuleImport_txt = """
	struct PspModuleImport{
		char *name;
		unsigned int flags;
		unsigned char  entry_size;
		unsigned char  var_count;
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
# 6th component is ptr to stubs, aka 'imports'
imports_addr = sceModuleInfo.getComponent(5).getValue()
# 7th component is stubs end
imports_end = sceModuleInfo.getComponent(6).getValue()
# undefine .lib.stub section members
currentProgram.getListing().clearCodeUnits(imports_addr, imports_end, False)

# create array of PspModuleImport
import_t = createPSPModuleImportStruct()
import_t_len = import_t.getLength()
currentProgram.getListing().createData(imports_addr, ArrayDataType(import_t, imports_end.subtract(imports_addr)/import_t_len, import_t_len))

# Ghidra hack to get the current directory to load data files
script_path = os.path.dirname(getSourceFile().getCanonicalPath())

# load NID database from https://github.com/mathieulh/PSP-PRX-Libraries-Documentation-Project
nidDB = ET.parse(os.path.join(script_path, "500_psplibdoc_191008.xml"))

# iterate through array of library imports
modules = getDataAt(imports_addr)
for index in range(modules.numComponents):
	# grab this module out of the array of PspModuleImport
	module = modules.getComponent(index)
	# roundabout way to grab the string pointed to by the name field
	module_name = getDataAt(module.getComponent(0).value).value
	# another roundabout way to get an actual number
	num_funcs = module.getComponent(4).value.getUnsignedValue()
	nids_base = module.getComponent(5).value
	stub_base = module.getComponent(6).value
	# convert raw data to DWORDs to 'show' NIDs
	createDwords(nids_base, num_funcs)
	# label the NIDs with the module name
	createLabel(nids_base, module_name+"_nids", True)

	print "Reolving NIDs for",module_name
	for func_idx in range(num_funcs):
		nid_addr = nids_base.add(4*func_idx)
		stub_addr = stub_base.add(func_idx * 8)
		# get NID hex and convert to uppercase
		nid = str(getDataAt(nid_addr).value).upper()
		# ensure 0x instead of 0X
		nid = nid.replace('X', 'x')
		# resolve NID to function name
		label = getFuncNameFromLibAndNID(nidDB.getroot(), module_name, nid)
		# delete any existing function so we can re-name it
		df = DeleteFunctionCmd(stub_addr, True)
		df.applyTo(currentProgram)
		# create a function with the proper name
		createFunction(stub_addr, label)
