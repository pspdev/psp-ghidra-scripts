# psp-ghidra-scripts
A collection of scripts to aid in reverse engineering PSP binaries in [Ghidra](https://ghidra-sre.org/)

## Installation
From Ghidra's `Script Manager` window, press the `Script Directories` button and add the directory of your working copy.

## Running
Double click the script name from the `Script Manager` window, ie `SonyPSPResolveNIDs.py`

## Scripts
### SonyPSPResolveNIDs
This tool resolves NIDs to library and function names by using the XML files from the [PSP PRX Libraries Documentation Project](https://github.com/mathieulh/PSP-PRX-Libraries-Documentation-Project)

### SonyPSPMapHWRegisters
This tool adds memory mapping for the PSP hardware registers. Useful when reverse engineering the kernel.

