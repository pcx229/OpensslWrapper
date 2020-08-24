# openssl

simple openssl library elliptic curves and hash wrapper

built on openssl version 1.1.1 and c++ version 11

## installing and compiling

## windows MinGW

download openssl for MinGW to the version of windows you have from the here - https://wiki.openssl.org/index.php/Binaries  
compiling command example(replace path to where your openssl libraries folder is located):

`g++ "-LC:\\Program Files\\OpenSSL-Win64\\mingw\\lib" -o MyProgram.exe *.cpp -lssl -lcrypto`

#### setting up eclipse

click on your project, then in the menu **Project -> Properties -> C\C++ Build -> Settings**  
in **Tool Settings -> GCC C++ Compiler -> Includes** add to **Include Paths** the include folder that is in your openssl installation folder.  
in **Tool Settings -> GCC C++ Compiler -> Miscellaneous** add to **Other flags** a flag **-std=c++0x** to specify C++ version 11  
if you are using a later version this flag may be useful to hide deprecated warnings  
in **Tool Settings -> GCC C++ Compiler -> Debugging** add to **Other debugging flags** a flag **-Wno-deprecated-declarations**  

## Unix

to install the development package `sudo apt-get install libssl-dev`

alternatively compiling form source - not necessary, will install the last development version  
note: when using the latest version of openssl some things may not work.  
      you should consider using the flag **-Wno-deprecated-declarations** when compiling to hide deprecated wornings  

```
git clone git://git.openssl.org/openssl.git
cd openssl
./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl
make
sudo make install
sudo ldconfig
```
