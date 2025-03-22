/* Copyright 2025 owl

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. */

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define cvector_clib_malloc emalloc
#define cvector_clib_calloc ecalloc
#define cvector_clib_realloc erealloc
#include "cvector.h"

//#define PRINT_BUT_DONT_EXEC

#define code_trap() code_append("\xcc")

static void
usage(char *argv0)
{
	fprintf(stderr, "usage: %s [file]\n", argv0);
	exit(1);
}

static void
die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (*fmt && fmt[strlen(fmt) - 1] == ':') {
		fputc(' ', stderr);
		perror(NULL);
	} else {
		fputc('\n', stderr);
	}

	exit(1);
}

static void *
emalloc(size_t size)
{
	void *p;

	if (!(p = malloc(size)))
		die("emalloc:");

	return p;
}

static void *
ecalloc(size_t nmemb, size_t size)
{
	void *p;

	if (!(p = calloc(nmemb, size)))
		die("ecalloc:");

	return p;
}

static void *
erealloc(void *ptr, size_t size)
{
	void *p;

	if (!(p = realloc(ptr, size)))
		die("erealloc:");

	return p;
}

int
main(int argc, char *argv[])
{
	if (argc != 2)
		usage(argv[0]);

	FILE *f = fopen(argv[1], "r");
	if (!f)
		die("cannot access '%s':", argv[1]);

	struct stat st;
	fstat(fileno(f), &st);

	char *txt = emalloc(st.st_size);
	fread(txt, st.st_size, 1, f);
	fclose(f);

	cvector(char) code = NULL;
	cvector_reserve(code, 512);

	cvector(uintptr_t) jmps = NULL;
	cvector_reserve(code, 16);

#define code_append(snip_)                                       \
	do {                                                         \
		size_t snip_size_ = sizeof snip_ / sizeof *snip_ - 1;    \
		cvector_reserve(code, cvector_size(code) + snip_size_);  \
		memcpy(code + cvector_size(code), snip_, snip_size_);    \
		cvector_set_size(code, cvector_size(code) + snip_size_); \
	} while (0)

	code_append("\x48\x89\xf8"); // mov rax, rdi

	for (char *s = txt; *s; s++)
		switch (*s) {
		case '>':
		case '<': {
			int n = 0;
			for (s--; s[1] == '>' || s[1] == '<'; s++)
				s[1] == '>' ? n++ : n--;

			if (n == 1)
				code_append("\x48\xff\xc0"); // inc rax
			else if (n == -1)
				code_append("\x48\xff\xc8"); // dec rax
			else if (n > 0) {
				assert(n <= UCHAR_MAX);
				code_append("\x48\x83\xc0"); // add rax, imm8
				cvector_push_back(code, n);
			} else if (n < 0) {
				assert(-n <= UCHAR_MAX);
				code_append("\x48\x83\xe8"); // sub rax, imm8
				cvector_push_back(code, -n);
			}

			break;
		}
		case '+':
		case '-': {
			int n = 0;
			for (s--; s[1] == '+' || s[1] == '-'; s++)
				s[1] == '+' ? n++ : n--;

			if (n == 1)
				code_append("\xfe\x00"); // inc BYTE PTR [rax]
			else if (n == -1)
				code_append("\xfe\x08"); // dec BYTE PTR [rax]
			else if (n > 0) {
				assert(n <= UCHAR_MAX);
				code_append("\x80\x00"); // add BYTE PTR [rax], imm8
				cvector_push_back(code, n);
			} else if (n < 0) {
				assert(-n <= UCHAR_MAX);
				code_append("\x80\x28"); // sub BYTE PTR [rax], imm8
				cvector_push_back(code, -n);
			}

			break;
		}
		case '.': {
			const char snip[] = "\x48\x89\xc6"  // mov rsi, rax
								"\x48\x31\xc0"  // xor rax, rax
								"\x48\xff\xc0"  // inc rax
								"\x48\x89\xc7"  // mov rdi, rax
								"\x48\x89\xc2"  // mov rdx, rax
								"\x0f\x05"      // syscall
								"\x48\x89\xf0"; // mov rax, rsi

			code_append(snip);
			break;
		}
		case ',': {
			const char snip[] = "\x48\x89\xc6"  // mov rsi, rax
								"\x48\x31\xc0"  // xor rax, rax
								"\x48\x31\xff"  // xor rdi, rdi
								"\x48\xff\xc7"  // inc rdi
								"\x0f\x05"      // syscall
								"\x48\x89\xf0"; // mov rax, rsi

			code_append(snip);
			break;
		}
		case '[': cvector_push_back(jmps, cvector_size(code)); break; // TODO: Implement forward jump-if-zero
		case ']': {
			code_append("\x80\x38\x00"); // cmp BYTE PTR [rax], 0

			int rel = jmps[cvector_size(jmps) - 1] - (cvector_size(code) + 2);
			cvector_pop_back(jmps);

			if (rel >= CHAR_MIN && rel <= CHAR_MAX) {
				code_append("\x75"); // jnz rel8
				cvector_push_back(code, rel);
			} else {
				code_append("\x0f\x85"); // jnz rel32

				const char relbytes[5];
				*(int *)relbytes = rel + 1;
				code_append(relbytes);
			}

			break;
		}
		default: break;
		}

	free(txt);
	cvector_free(jmps);

	code_append("\xc3"); // ret

	void *fn = mmap(NULL, cvector_size(code), PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!fn)
		die("could not allocate executable memory:");

#ifdef PRINT_BUT_DONT_EXEC
	fwrite(code, cvector_size(code), 1, stdout);

	return 0;
#endif

	memcpy(fn, code, cvector_size(code));
	mprotect(fn, cvector_size(code), PROT_EXEC);
	cvector_free(code);

	char *buf = ecalloc(30000, 1);
	(*(void (**)(void *))&fn)(buf);
	// leak buf on purpose

	return 0;
}
