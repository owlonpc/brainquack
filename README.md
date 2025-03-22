# brainquack

## Compiling
Simply run `make`. Optionally adjust CFLAGS and such in Makefile.

## Tests
Run `make test` to test included "Hello World" program using current Makefile settings.

Run `test.bash` to test included "Hello World" program using various compilers, libcs, and flags. (Depends on GNU Parallel)

## Usage
`./bf [file]`

## Dependencies
All you need is a C99 compiler and make.

Includes [cvector](https://github.com/eteran/c-vector) single-header library for dynamic arrays. (MIT License)

## License
Copyright 2025 owl

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
