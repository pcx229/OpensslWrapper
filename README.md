# OpensslWrapper

simple openssl library elliptic curves and hash wrapper

built on openssl version 1.1.1 and c++ version 11

## Installing And Compiling

## Windows MinGW

download openssl developers edition for MinGW to the version of windows you have from here:  
https://slproweb.com/products/Win32OpenSSL.html  
`note:` this version of openssl require linking .lib files, with MinGW64 i had issus trying to link this type of file so the project was built on the base MinGW version.  

#### using newer version of openssl:

if you are using a later version this flag may be useful to hide deprecated warnings **-Wno-deprecated-declarations**    

#### OPENSSL_Uplink error

my setup was giving me `OPENSSL_Uplink(00007FFA43EF9D30,08): no OPENSSL_Applink` error when trying using any openssl function that was handling files.  
to fix that you need to add `#include <openssl/applink.c>` to the main file of your program or remembering to build it with the rest of your code.  
that file in my openssl MinGW build was having syntax issues, so the file included in the source directory is a fixed version of that file that works.  

#### using Google Tests Runner framework

tests are built on this framework, so its required to install it if those are needed.  
installation guide:  

1. download and install CMake from here https://cmake.org/download/
2. download Google Tests Runner framework from here https://github.com/google/googletest
3. building Google Tests Runner with CMake
	* make sure MinGW bin directory is in your system path
	* open command line and go to Google Tests Runner root project directory
	* type:  
```
mkdir build  
cd build  
cmake .. -G "MinGW Makefiles"  
mingw32-make 
```

4. link libraries path {Google Tests Runner root project path}/build/lib to your project, and include libraries 'gtest', 'gtest_main'  

#### setting up eclipse

click on your project, then in the menu **Project -> Properties -> C\C++ Build -> Settings -> Tool Setting tab**  
- **GCC C++ Compiler -> Includes** add to **Include Paths** the include directory that is in your openssl installation directory.  
- **MinGW C++ Linker -> Libraries** and add to **Libraries (-l)** section **libssl** and **libcrypto**  
- **MinGW C++ Linker -> Libraries** and add to **Library search path (-L)** section **C:\Program Files\OpenSSL-Win64\lib** (path to where your openssl libraries directory is located)  

optional hide deprecated:  

- **GCC C++ Compiler -> Debugging** add to **Other debugging flags** a flag **-Wno-deprecated-declarations**  

set c++ version 11:  
- **GCC C++ Compiler -> Miscellaneous** add to **Other flags** the flag **-std=c++11**

click on your project, then in the menu **Project -> Properties -> C\C++ General -> Preprocessor Include -> Providers -> CDT Cross GCC Built-in Compiler Settings**
  - uncheck **Use global provider shared between projects**  
  - add to **Command to get compiler specs** line **-std=c++11** in the end    

Google Test and eclipse:  
- include path to src directory from test directory in the settings by right clicking
on the test directory **Propeties -> C/C++ General -> Paths and Symbols -> Includes Tab -> GNU C++** and add workspace src directory path.  
- link libraries path {Google Test root project path}/build/lib to your project, and include libraries 'gtest', 'gtest_main'  
- click on your project, then in the menu **Project -> Properties -> C\C++ Build -> Settings -> Tool Setting tab** **MinGW C++ Linker -> Libraries** 
  - **Libraries (-l)** section add **gtest** and **gtest_main**  
  - **Library search path (-L)** section add **"C:\googletest-master\build\lib"** (path to where your Google Test framework libraries directory is located)  
- for visual testing GUI go to **Run -> Run Configurations... -> C/C++ Unit** select **New**, in tab **C/C++ Testing** pick **Test Runner** as **Google Tests Runner** - now you can run the program in testing mode when you execute with this configuration no main program required
* `note:` test mode will only be active when no main function has been found in the build, to remove from build right click on the file or folder, then go to **Resource Configurations->Exclude from Build...**  
	
#### compiling

command for example(replace path to where your openssl libraries directory is located):

`g++ -std=c++11 "-LC:\\Program Files\\OpenSSL-Win64\\lib" -o MyProgram.exe *.cpp -llibssl -llibcrypto`

