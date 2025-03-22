# Copyright 2025 owl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CPPFLAGS = -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
CFLAGS   = -std=c99 -pedantic -Wall -Wextra -Og -ggdb3 ${CPPFLAGS}
CC       = cc

bf: bf.c
	${CC} -o $@ ${CFLAGS} $<

bf: Makefile

test: bf
	[ "`./bf hello.bf`" = "Hello World!" ]

clean:
	rm -f bf bf.tar.gz

dist: clean
	mkdir bf
	cp Makefile .clang-format compile_flags.txt cvector.h bf.c hello.bf test.bash bf
	tar -cf bf.tar bf
	gzip -9 bf.tar
	rm -rf bf

.PHONY: test clean dist
