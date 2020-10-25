# Lib86cpu

"lib86cpu" is an open source library that emulates an Intel Pentium III processor, and exposes its functionality
via its own API. It uses a custom frontend to translate the guest code to LLVM IR, and then uses LLVM as the
backend to emit native code for the target platform.

## Building

Cmake version 3.4.3 or higher is required.\
Visual Studio 2019.\
Only Windows builds are supported for now.

**On Windows:**

`git clone --recurse-submodules https://github.com/ergo720/lib86cpu`\
Build LLVM according to the instructions [here](https://llvm.org/docs/GettingStartedVS.html)\
`cd` to the directory of lib86cpu\
`mkdir build && cd build`\
`cmake .. -G "Visual Studio 16 2019" -A Win32`\
Build the resulting solution file lib86cpu.sln with Visual Studio

**NOTE:** use `cmake .. -G "Visual Studio 16 2019" -A Win32 -DLIB86CPU_BUILD_TEST=ON` if you want to also build the test app
