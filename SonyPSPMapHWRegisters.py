#Add a mapping for hardware registers
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

import ghidra.program.model.address

hw_memory_map = [
	(0xBC000000, 0x0054, "HW_SYSMEM"),
	(0xBC100000, 0x0104, "HW_SYS_CONTROL"),
	(0xBC200000, 0x0008, "HW_FREQ"),
	(0xBC300000, 0x002C, "HW_INTR"),
	(0xBC400000, 0x0054, "HW_PROF"),
	(0xBC500000, 0x0410, "HW_HWTIMER"),
	(0xBC600000, 0x0014, "HW_SYSTIME"),
	(0xBC800000, 0x01D0, "HW_DMACPLUS"),
	(0xBC900000, 0x01F0, "HW_DMAC_1"),
	(0xBCA00000, 0x01F0, "HW_DMAC_2"),
	(0xBCC00000, 0x0074, "HW_VME"),
	(0xBD000000, 0x0048, "HW_DDR"),
	(0xBD100000, 0x1304, "HW_NANDFLASH"),
	(0xBD200000, 0x0044, "HW_MEMSTICK"),
	(0xBD300000, 0x0044, "HW_WLAN"),
	(0xBD400000, 0x0E80, "HW_GE"),
	(0xBD500000, 0x00A4, "HW_GE_EDRAM"),
	(0xBD600000, 0x0048, "HW_ATAUMD_1"),
	(0xBD700000, 0x0010, "HW_ATAUMD_2"),
	(0xBD800000, 0x0518, "HW_USB"),
	(0xBD900000, 0x0048, "HW_EFLASH"),
	(0xBDA00000, 0x0010, "HW_EFLASH_ATA"),
	(0xBDB00000, 0x0048, "HW_EFLASH_DMA"),
	(0xBDE00000, 0x0054, "HW_KIRK"),
	(0xBDF00000, 0x0098, "HW_UMD"),
	(0xBE000000, 0x00D4, "HW_AUDIO"),
	(0xBE100000, 0x00A4, "HW_MAGICGATE"),
	(0xBE140000, 0x0204, "HW_LCDC"),
	(0xBE200000, 0x0030, "HW_I2C"),
	(0xBE240000, 0x004C, "HW_GPIO"),
	(0xBE300000, 0x0060, "HW_POWER"),
	(0xBE4C0000, 0x0048, "HW_UART_1"),
	(0xBE500000, 0x0048, "HW_UART_2"),
	(0xBE580000, 0x0028, "HW_SYSCON"),
	(0xBE5C0000, 0x0028, "HW_LCD_SLIM"),
	(0xBE740000, 0x0028, "HW_DISPLAY"),
	(0xBE780000, 0x0020, "HW_DISPLAY_SLIM"),
	#(0xBFC00000, 0x100000, "RESET_VECTOR")
]

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def main():
    mem = currentProgram.getMemory()
    for (addr, size, name) in hw_memory_map:
        block = mem.createUninitializedBlock(name, getAddress(addr), size, False)
        block.setRead(True)
        block.setWrite(True)
        block.setVolatile(True)
        block.setExecute(False)
        print "Added", block

if __name__ == "__main__":
    main()
