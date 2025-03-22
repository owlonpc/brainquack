#!/bin/bash

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

testing() {
	output=`mktemp`
	flags="$2 $3"

	$1 -o $output $flags bq.c
	if [ $? -ne 0 ]; then
		echo $1 \($flags\): COMPILATION FAILED!
		rm $output
		exit
	fi

	[ "`$output hello.bf`" = "Hello World!" ]
	if [ $? -ne 0 ]; then
		echo $1 \($flags\): EXECUTION FAILED!
		rm $output
		exit
	fi
	rm $output
}

export -f testing
parallel testing ::: gcc clang musl-gcc musl-clang ::: -O0 -O -O2 -O3 -Os -Og ::: -flto -fno-lto