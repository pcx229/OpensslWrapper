# OpensslWrapper

simple openssl library elliptic curves and hash wrapper

built on openssl version 1.1.1 and c++ version 11

## Installing And Compiling

## Windows MinGW

download openssl developers edition for MinGW to the version of windows you have from here:  
https://slproweb.com/products/Win32OpenSSL.html  

#### using newer version of openssl:
if you are using a later version this flag may be useful to hide deprecated warnings **-Wno-deprecated-declarations**    

#### OPENSSL_Uplink error:

my setup was giving me `OPENSSL_Uplink(00007FFA43EF9D30,08): no OPENSSL_Applink` error when trying to use any openssl function that was handling files.  
to fix that you need to add `#include <openssl/applink.c>` to the main file of your program or remembering to build it with the rest of your code.  
that file in my openssl MinGW build was having syntax issues, so the file included in the source directory is a fixed version of that file that works.  

#### setting up eclipse

click on your project, then in the menu **Project -> Properties -> C\C++ Build -> Settings**  
**Tool Settings -> GCC C++ Compiler -> Includes** add to **Include Paths** the include folder that is in your openssl installation folder.  
**Tool Settings -> GCC C++ Compiler -> Miscellaneous** add to **Other flags** a flag **-std=c++0x** to specify C++ version 11  
**MinGW C++ Linker -> Libraries**  
* **Libraries (-l)** section add **libssl** and **libcrypto**  
* **Library search path (-L)** add **C:\Program Files\OpenSSL-Win64\lib** (path to where your openssl libraries folder is located)  

optinal hide deprecated:  
**Tool Settings -> GCC C++ Compiler -> Debugging** add to **Other debugging flags** a flag **-Wno-deprecated-declarations**  

#### compiling  
command for example(replace path to where your openssl libraries folder is located):

`g++ "-LC:\\Program Files\\OpenSSL-Win64\\lib" -o MyProgram.exe *.cpp -llibssl -llibcrypto`

## Unix

to install the development package `sudo apt-get install libssl-dev`

alternatively compiling form source - not necessary, will install the last development version  
* *note:*  
when using the latest version of openssl some things may not work.  
you should consider using the flag **-Wno-deprecated-declarations** when compiling to hide deprecated warnings.  

```
git clone git://git.openssl.org/openssl.git
cd openssl
./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl
make
sudo make install
sudo ldconfig
```

#### compiling  
command for example:

`g++ -o MyProgram.exe *.cpp -lssl -lcrypto`
