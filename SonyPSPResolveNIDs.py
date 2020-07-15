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

# undefine .lib.stub section members
stubs = currentProgram.getMemory().getBlock(".lib.stub");
currentProgram.getListing().clearCodeUnits(stubs.getStart(), stubs.getEnd(), False)

# create array of PspModuleImport
import_t = createPSPModuleImportStruct()
import_t_len = import_t.getLength()
currentProgram.getListing().createData(stubs.getStart(), ArrayDataType(import_t, stubs.getSize()/import_t_len, import_t_len))

# Ghidra hack to get the current directory to load data files
script_path = os.path.dirname(getSourceFile().getCanonicalPath())

# load NID database from https://github.com/mathieulh/PSP-PRX-Libraries-Documentation-Project
nidDB = ET.parse(os.path.join(script_path, "150_psplibdoc_201008.xml"))

# iterate through array of library imports
modules = getDataAt(stubs.getStart())
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
