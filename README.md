# brainquack
Simple x86-64 Linux JIT compiler for the brainfuck programming language. 

## Compiling
Simply run `make`. Optionally adjust CFLAGS and such in Makefile.

## Tests
Run `make test` to test included programs using current Makefile settings. (Depends on GNU Parallel)

## Usage
`./bq [file]`

## Dependencies
All you need is a C99 compiler and make.

Includes [cvector](https://github.com/eteran/c-vector) single-header library for dynamic arrays. (MIT License)

## License
Copyright 2025 owl

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

Programs in `tests` directory are made by Daniel B. Cristofani (https://www.brainfuck.org/) and are licensed under [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).