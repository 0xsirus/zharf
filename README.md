# ZHARF fuzzer

### (This work is currently under development and submission)

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
<img src="https://www.cs.utah.edu/~sirus/zharf-1.1.png" />

### Some notes about fuzzing speed
Zharf performs dynamic graph analysis which is computationally costly. The speed
of fuzzing can be drastically affected by the size of the program under fuzz. If
the reported speed by the fuzzer is less than 50 iterations per second, you must
decrease the instrumentation ratio by passing "ZCC\_RATIO" environmental
variable to `zcc` for compiling the program you want to fuzz. This variable
defines to what extend the program should be instrumented. The more aggressively
the program is instrumented, the more trace information Zharf has to analyze the
program but at the same time the slower the fuzzing will be. By default this
ratio is 1 which is the maximum ratio. Passing values less than one will
increase speed and decrease the analysis accuracy. But for big programs, the
speed gain well outweighs the precision loss. If you want to use this variable,
it's recommended to pass a value between 0.2 and 0.8 based on the speed change
that you observe in the fuzzer board.

Example: Compiling a program and passing 80% for `ZCC\_RATIO':
```
ZCC_RATIO=0.8 zcc -o program.elf program.c
```
