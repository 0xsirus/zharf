# ZHARF fuzzer
<img src="https://www.cs.utah.edu/~sirus/zharf.gif" />

Compilation and usage of the fuzzer is pretty straightforward. To compile Zharf,
just enter the directory and run:
```
$ make
```
Note that you need `gcc 8.1` or newer to be able to compile this code.

It's best to install the zharf library in your system before starting the fuzzer.
```
# make install
```
If you choose not to install the library, you have to start the fuzzer from the
directory that has `libzh.so` in it.

Fuzzing programs using Zharf is also simple. No pre-processing is needed apart
from compiling the target program with `zcc` instead of `gcc`.  You will compile
your program with the compiler bridge `zcc` that has been provided exactly the
same way you would compile a `C` file or package using `gcc`.

Example:
```
$ CC=zcc ./configure
$ make
```
`zcc` instruments the target program to be fuzzed by Zharf.

Basic arguments to run the fuzzer are 'input_directory', 'output_directory' and
the path to the executable that has been instrumented and you want to fuzz.
```
$ zharf -i input_dir -o output_dir program.elf <program arguments>
```

Example: Fuzzing a program that reads its input from `/tmp/input0` while the
initial seeds are stored in `input_dir`:
```
$ zcc -o program.elf program.c
$ zharf -i input_dir -o output_dir -f /tmp/input0 program.elf /tmp/input0
```

To see all options run:
```
$ zharf -h
```
<img src="https://www.cs.utah.edu/~sirus/zharf_1.1.png" />

