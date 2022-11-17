# Lib86cpu

"lib86cpu" is an dynamic recompiler library that emulates an Intel Pentium III processor, and exposes its functionality
via its own API.

### Supported host architectures
- x86-64

There are no plans to support x86-32.

## Building

Cmake version 3.4.3 or higher is required.\
Visual Studio 2022.\
Only Windows builds are supported for now.

**On Windows:**

1. `cd` to the directory of lib86cpu
2. `mkdir build && cd build`
3. `cmake .. -G "Visual Studio 17 2022" -A x64 -Thost=x64`
4. Build the resulting solution file lib86cpu.sln with Visual Studio

**NOTE:** use `-DLIB86CPU_BUILD_TEST=ON` if you want to also build the test app.
