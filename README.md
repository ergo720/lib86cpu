# Lib86cpu

"lib86cpu" is an dynamic recompiler library that emulates an Intel Pentium III Coppermine processor, and exposes its functionality
via its own API. Specifically, it emulates the Pentium III processor found on the original Xbox console.

### Supported host architectures
- x86-64

There are no plans to support x86-32.

## Building

Cmake version 3.4.3 or higher is required.\
Visual Studio 2022 (Windows), Visual Studio Code (Linux, optional).\
NOTE: there is a known bug in a version of Visual Studio 2022 after 17.1.5, that prevents the project from building successfully, so use a version equal or prior to that.

**On Windows:**

1. `git clone --recurse-submodules https://github.com/ergo720/lib86cpu`
2. `cd` to the directory of lib86cpu
3. `mkdir build && cd build`
4. `cmake .. -G "Visual Studio 17 2022" -A x64 -Thost=x64`
5. Build the resulting solution file lib86cpu.sln with Visual Studio

**On Linux:**

1. `git clone --recurse-submodules https://github.com/ergo720/lib86cpu`
2. `cd` to the directory of lib86cpu
3. `mkdir build && cd build`
4. `cmake .. -G "Unix Makefiles"`
5. Build the resulting Makefile with make, or use Visual Studio Code

**NOTE:** use `-DLIB86CPU_BUILD_TEST=ON` if you want to also build the test app.

## Support

You can show your appreciation to this project to the below addresses:
- Bitcoin `1NnaFQoj6MMFZWFk8ETmKE4qUKpzhZxZ2g`
- Ether   `0x340aeB056C1Cf9107FAc476371D2b2d0544b50cf`
