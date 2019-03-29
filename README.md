# bn-angr works only on Linux !!! 
Symbolic execution for static vulnerability assessment in firmware

#### Example base on vulnerability found in IoT device

##### 1) angr should be installed on virtualenv, and binaryninja executed from

##### 2) angr + BN works only on Linux without issues

##### 3) virtualenv require python 3.x

###### virtualenv -p /usr/bin/python3 angr

##### change path in binaryninja to point to python3 of your main os

##### 4) Angr has some issues on virtualenv for python3. In order to solve that

###### update ~/yourpath/angr/lib/python3.5/site-packages/cle/backends/binja.py

###### line  if magic.startswith("SQLite format 3") and stream.name.endswith("bndb"):
###### replace with if magic.startswith(b"SQLite format 3") and stream.name.endswith("bndb"):

##### 5) update ~/yourpath/angr/lib/python3.5/site-packages/cle/backends/elf/metaelf.py

###### with this changes https://github.com/angr/cle/commit/ff2bee1191885441fb2ebbfcae9aafca2eea69c6

##### 6) to support pwntools inside virtualenv and binaryninja

###### inside virtualenv pip install pwntools
###### git clone https://github.com/arthaud/python3-pwntools
###### cd python3-pwntools
###### pip3 install -e .

###### edit your .bashrc or .zshrc file with export PWNLIB_NOTERM=true

![Alt text](docs/images/bn-angr.png?raw=true "Angr binaryninja plugin UI")
![Alt text](docs/images/bn-angr2.png?raw=true "Angr binaryninja plugin UI")
![Alt text](docs/images/rop.png?raw=true "ROP exploitation example")
![Alt text](docs/images/rop.png?raw=true "ROP stack example")
![Alt text](docs/images/rop-stack.png?raw=true "ROP stack example")
