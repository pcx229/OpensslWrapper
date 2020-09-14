# OpensslWrapper

simple wrapper for openssl elliptic curves and hash libraries

built on openssl version 1.1.1 and c++ version 11

## Installing And Compiling

## Windows MinGW

the project was built with MinGW64 POSIX 32bit and openssl 1.1.1 32bit from here:  
https://bintray.com/vszakats/generic/openssl  
`note:` MinGW64 is essential since use of C++11 POSIX threads is required.  

download openssl developers edition for MinGW to the version of windows you have from here:  
https://slproweb.com/products/Win32OpenSSL.html  
`note:` this version of openssl require linking .lib files, with MinGW64 i had issus trying to link this type of file so the project was built on the base MinGW version.  

#### using newer version of openssl:

if you are using a later version this flag may be useful to hide deprecated warnings **-Wno-deprecated-declarations**    

#### OPENSSL_Uplink error

if you get `OPENSSL_Uplink(00007FFA43EF9D30,08): no OPENSSL_Applink` error when trying using any openssl function that is handling files,  
you can fix that by adding `#include <openssl/applink.c>` to the main file of your program or remembering to build it with the rest of your code.  

#### program runs but nothing happens

copy dlls from openssl installation directory libcrypto-1_1.dll and libssl-1_1.dll to your .exe file directory. (in some cases it's required to rename the files to libcrypto.dll and libssl.dll)

#### "undefined reference" errors 

in my experience this problem seems to be related to the version of the binaries you are linking 32bit or 64bit  
that might conflict with the version of you MinGW.  
i've tried many configurations of openssl with MinGW and MinGW64, and got this problem in many occasions, its 
seems that the combination of MinGW64 32bit and the openssl 32bit linked above works together ok.

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

4. link libraries path **{Google Tests Runner root project path}/build/lib** to your project, and use those libraries **gtest**, **gtest_main** when compiling.  

#### setting up eclipse

click on your project, then in the menu **Project -> Properties -> C\C++ Build -> Settings -> Tool Setting tab**  
- **GCC C++ Compiler -> Includes** add to **Include Paths** the include directory that is in your openssl installation directory.  
- **MinGW C++ Linker -> Libraries** and add to **Libraries (-l)** section **ssl** and **crypto**  
- **MinGW C++ Linker -> Libraries** and add to **Library search path (-L)** section **C:\openssl-1.1.1g-win32-mingw\lib** (path to where your openssl libraries directory is located)  

optional hide deprecated:  

- **GCC C++ Compiler -> Debugging** add to **Other debugging flags** a flag **-Wno-deprecated-declarations**  

set c++ version 11:  
- **GCC C++ Compiler -> Miscellaneous** add to **Other flags** the flag **-std=c++11**

- click on your project, then in the menu **Project -> Properties -> C\C++ General -> Preprocessor Include -> Providers -> CDT Cross GCC Built-in Compiler Settings**
  - uncheck **Use global provider shared between projects**  
  - add to **Command to get compiler specs** line **-std=c++11** in the end    

Google Test and eclipse:  
click on your project, then in the menu **Project -> Properties -> C\C++ Build -> Settings -> Tool Setting tab**  
- **GCC C++ Compiler -> Includes** add to **Include Paths** the include directory that is in your Google Test Runner installation directory.  
- **MinGW C++ Linker -> Libraries** and add to **Libraries (-l)** section **gtest** and **gtest_main**  
- **MinGW C++ Linker -> Libraries** and add to **Library search path (-L)** section **C:\googletest-master\build\lib** (path to where your Google Test Runner libraries directory is located)  
- include path to src directory from test directory in the settings by right clicking
on the test directory **Propeties -> C/C++ General -> Paths and Symbols -> Includes Tab -> GNU C++** and add workspace src directory path.  
- for visual testing GUI go to **Run -> Run Configurations... -> C/C++ Unit** select **New**, in tab **C/C++ Testing** pick **Test Runner** as **Google Tests Runner** - now you can run the program in testing mode when you execute with this configuration no main program required
* `note:` test mode will only be active when no main function has been found in the build, to remove from build right click on the file or folder, then go to **Resource Configurations->Exclude from Build...**  
	
#### compiling

command for example(replace path to where your openssl libraries directory is located):

`g++ -std=c++11 "-LC:\\Program Files\\OpenSSL-Win64\\lib" -o MyProgram.exe *.cpp -lssl -lcrypto`

## Shared Context

many functions in the openssl library requires context data(dump) for calculation purposes, the context is predefined by the programer and 
passed to the function that needs it manually.
for example:

``` c++
BN_CTX *ctx; // context for BIGNUM calculations
BN_CTX_new(ctx); //  context allocation
BN_mul(r, a, b, ctx); // usage
BN_CTX_free(ctx); //  deallocation
```

when trying to wrap a library like 'bn' in a class to perform different functions such arithmetic in a less cumbersome way
there comes a need for a context to be bond locally in the class.  
creating many instances for that class will build many contexts dumps, that will be unused most of the time.  
one solution is to make the context static, then only one instance is built.  
the problem is that some usage of the context are chained, for example:

``` c++
EVP_DigestInit_ex(ctx, md, NULL)
EVP_DigestUpdate(ctx, data, size)
// using the context here for unrelated operations will corrupt the digest result!
EVP_DigestFinal_ex(ctx, md_value, &md_len)
```

so data corruption can occurer with this approach, but for only single operation with a single thread it can be sufficient.  
a better solution is a system that manage a pool of contexts and give it to anyone who needs it, when he needs it.  
and thats how SharedContext_ex class works, it assign a minimum of one context of any type for each thread if at least one was required in the program.  
also you can lock the context and prevent others from using it when a chain operation is needed.  

usage:  

single operation:

``` c++
BN_SHARED_CONTEXT ctx;
BN_mul(r, a, b, ctx);
```

chain operations:

``` c++
EVP_MD_SHARED_CONTEXT ctx;
ctx.lock(); // prevent others from using this context
EVP_DigestInit_ex(ctx, md, NULL)
// getting another/or using existing instance of this thread
// context type in between is now possible without damaging this context
EVP_DigestUpdate(ctx, data, size)
EVP_DigestFinal_ex(ctx, md_value, &md_len)
ctx.unlock();
```

*no need to free the context at the end  

building a shared context for a type can be done by the following declaration:  

```typedef SharedContext_ex<EVP_MD_CTX, EVP_MD_CTX_new, EVP_MD_CTX_free, EVP_MD_CTX_copy>::temporary EVP_MD_SHARED_CONTEXT```

disable shared context by adding the following in your main program:  

```
#undef SHARE_CONTEXT
```

## Example

creating a Bitcoin Public Address:  
 
``` c++
EC e;
string checksum, address;
string stage[10];

cout << "Calculating Bitcoin Public Address" << endl;

// 0 - a private ECDSA key
stage[0] = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
cout << "0) private key: " << stage[0] << endl;
// 1 - the corresponding public key
e.load_private_by_number(stage[0], secp256k1, HEX);
stage[1] = e.get_public_point(EC::public_key_point_format::COMPRESSED, HEX); // 0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352
cout << "1) public key: " << stage[1] << endl;
// 2 - sha256 hash on public key
stage[2] = Hash<sha256>(stage[1], HEX);
cout << "2) sha256 on public: " << stage[2] << endl;
// 3 - ripemd160 hash on last stage result
stage[3] = Hash<ripemd160>(stage[2], HEX);
cout << "3) ripemd160 on previous result: " << stage[3] << endl;
// 4 - add 0x00 byte at the beginning of previous stage result
//     this is a version byte for main network address
stage[4] = (stage[3]).insert(0, "00");
cout << "4) add version byte 0x00 to previous result: " << stage[4] << endl;
// 5 - sha256 hash on last stage result
stage[5] = Hash<sha256>(stage[4], HEX);
cout << "5) sha256 on previous result: " << stage[5] << endl;
// 6 - sha256 hash on last stage result
stage[6] = Hash<sha256>(stage[5], HEX);
cout << "6) sha256 on previous result: " << stage[6] << endl;
// 7 - the checksum is 4 bytes from the beginning of last stage result
stage[7].insert(0, stage[6], 0, 8);
cout << "7) checksum is: " << stage[7] << endl;
// 8 - add checksum to the end of stage 4 result
stage[8] = stage[4].append(stage[7]);
cout << "8) add checksum to the end of the extended ripemd160 result(4): " << stage[8] << endl;
// 9 - do base58 encoding on the last stage result
stage[9] = transfer(stage[8], HEX, BASE58);
cout << "9) base58 encoding on previous result: " << stage[9] << endl;

// extract wanted parameters
address = stage[9];
checksum = stage[7];

// results
cout << "address: " << address << endl;
cout << "checksum: " << checksum << endl;
```
