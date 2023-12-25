# Just In Time! Hooking Java Methods
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview
This project showcases how to easily hook Java methods by acquiring the JIT compiled code address and applying a detour.

You can find the full writeup [here](https://systemfailu.re/2023/12/25/hooking-java-methods-just-in-time/).

## Demo
A demo can be found [here](https://www.youtube.com/watch?v=ohEAT8cnsLw).

## Features
- Easy detection of JIT entrypoints
- Simple hook interface with examples
- Force compilation of a Java methods not yet compiled

## Requirements
- A java application to hook
- Knowledge of the class and method name/signature to hook
- Address of `CompileBroker::compile_method`
- CMake
- C++17 compiler

## Dependencies
This project uses hde64 for disassembly, which is developed by Vyacheslav Patkov.

## Building
To build the project, please use the provided CMakeLists.txt file.
```bash
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -T host=x64 -A x64
cmake --build . --config Release
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer
This project is for educational purposes only. 

I am well aware that a lot of the code is not production ready and that there are a lot of things that could be improved.