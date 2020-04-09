# Explorer plugin support Linux and OS X
# Tested on Ubuntu 18.04 LTS and OS X Catalina 

## For OS X you don't need to install virtualenv

Symbolic execution for static vulnerability assessment in firmware

#### SUPPORTED FEATURES
##### a) Set start/end address of execution
##### b) Dynamic recognition of numer and type of function params
##### c) Option to search for buffer overflow
##### d) Path exploration coloring 
##### e) Set library path and select library to load
##### f) ROP Chaining
##### g) ROP Stack 
##### h) Exploit PoC generation to JSON or file

#### Example base on vulnerability found in IoT device

##### 1) angr should be installed on virtualenv, and binaryninja executed from

##### 2) angr + BN works only on Linux without issues

##### 3) virtualenv require python 3.x

###### virtualenv -p /usr/bin/python3 angr

##### change path in binaryninja to point to python3 of your main os


![Alt text](docs/images/set_start.png?raw=true "Set execution start address")
![Alt text](docs/images/set_end.png?raw=true "Set execution end address")
![Alt text](docs/images/func_params.png?raw=true "Set function params")
![Alt text](docs/images/ld_path.png?raw=true "Set LD_PATH")
![Alt text](docs/images/ld_path2.png?raw=true "Set LD_PATH details")
![Alt text](docs/images/shared_lib.png?raw=true "Set Shared lib")
![Alt text](docs/images/libraries.png?raw=true "Set libraries")
![Alt text](docs/images/gen_exploit.png?raw=true "Exploit generation")
![Alt text](docs/images/bn-angr.png?raw=true "Angr binaryninja plugin UI")
![Alt text](docs/images/bn-angr2.png?raw=true "Angr binaryninja plugin UI")
![Alt text](docs/images/rop.png?raw=true "ROP exploitation example")
![Alt text](docs/images/rop-stack.png?raw=true "ROP stack example")
