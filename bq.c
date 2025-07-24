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
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define cvector_clib_malloc emalloc
#define cvector_clib_realloc erealloc
#include "cvector.h"

//#define PRINT_BUT_DONT_EXEC

#define code_trap() code_append("\xcc")

static char *tapeguardpage;

typedef enum { OP_MOVE, OP_ADD, OP_OUTPUT, OP_INPUT, OP_JUMP_RIGHT, OP_JUMP_LEFT, OP_CLEAR, OP_ADD_TO, OP_MOVE_UNTIL } Opcode;

typedef struct {
	Opcode op;
	int    arg;
} Instr;

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
erealloc(void *ptr, size_t size)
{
	void *p;

	if (!(p = realloc(ptr, size)))
		die("erealloc:");

	return p;
}

static bool
isop(char c)
{
	return strchr("><+-.,[]", c);
}

__attribute((noreturn)) static void
handler(int signum, siginfo_t *si, void *ucontext)
{
	(void)signum;
	(void)ucontext;

	if (si->si_addr >= (void *)tapeguardpage && si->si_addr < (void *)(tapeguardpage + getpagesize()))
		die("ran out of tape memory");

	SIG_DFL(signum);
	__builtin_unreachable();
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

	cvector(Instr) instrs = NULL;
	cvector_reserve(instrs, 128);

	for (char *s = txt; *s; s++) {
		Instr instr;
		switch (*s) {
		case '>':
		case '<': {
			int n = 0;
			for (s--; s[1] == '>' || s[1] == '<' || !isop(s[1]); s++)
				if (s[1] == '>')
					n++;
				else if (s[1] == '<')
					n--;

			if (n != 0) {
				instr = (Instr){ OP_MOVE, n };
				cvector_push_back(instrs, instr);
			}

			break;
		}
		case '+':
		case '-': {
			int n = 0;
			for (s--; s[1] == '+' || s[1] == '-' || !isop(s[1]); s++)
				if (s[1] == '+')
					n++;
				else if (s[1] == '-')
					n--;

			if (n != 0) {
				instr = (Instr){ OP_ADD, n };
				cvector_push_back(instrs, instr);
			}

			break;
		}
		case '.':
			instr.op = OP_OUTPUT;
			cvector_push_back(instrs, instr);
			break;
		case ',':
			instr.op = OP_INPUT;
			cvector_push_back(instrs, instr);
			break;
		case '[':
			instr.op = OP_JUMP_RIGHT;
			cvector_push_back(instrs, instr);
			break;
		case ']': {
			size_t len = cvector_size(instrs);

			// [-] or [+]
			if (len >= 2 && instrs[len - 1].op == OP_ADD && instrs[len - 1].arg & 1 && instrs[len - 2].op == OP_JUMP_RIGHT) {
				cvector_set_size(instrs, len - 2);
				instr.op = OP_CLEAR;
				cvector_push_back(instrs, instr);
				break;
			}

			// [->+<] or [-<+>]
			if (len >= 5 && instrs[len - 1].op == OP_MOVE && instrs[len - 2].op == OP_ADD && instrs[len - 2].arg == 1 &&
			    instrs[len - 3].op == OP_MOVE && instrs[len - 4].op == OP_ADD && instrs[len - 4].arg == -1 &&
			    instrs[len - 1].arg == -instrs[len - 3].arg && instrs[len - 5].op == OP_JUMP_RIGHT) {
				cvector_set_size(instrs, len - 5);
				instr = (Instr){ OP_ADD_TO, instrs[len - 3].arg };
				cvector_push_back(instrs, instr);
				break;
			}

			// [>] or [<]
			if (len >= 2 && instrs[len - 1].op == OP_MOVE && instrs[len - 2].op == OP_JUMP_RIGHT) {
				cvector_set_size(instrs, len - 2);
				instr = (Instr){ OP_MOVE_UNTIL, instrs[len - 1].arg };
				cvector_push_back(instrs, instr);
				break;
			}

			instr.op = OP_JUMP_LEFT;
			cvector_push_back(instrs, instr);
			break;
		}
		default: break;
		}
	}

	free(txt);

	cvector(char) code = NULL;
	cvector_reserve(code, 512);

	cvector(uintptr_t) jmps = NULL;
	cvector_reserve(jmps, 16);

	cvector(uintptr_t) putcharpatches = NULL;
	cvector_reserve(putcharpatches, 64);

	cvector(uintptr_t) getcharpatches = NULL;
	cvector_reserve(getcharpatches, 32);

#define code_append(snip_)                                       \
	do {                                                         \
		size_t snip_size_ = sizeof snip_ / sizeof *snip_ - 1;    \
		cvector_reserve(code, cvector_size(code) + snip_size_);  \
		memcpy(code + cvector_size(code), snip_, snip_size_);    \
		cvector_set_size(code, cvector_size(code) + snip_size_); \
	} while (0)

	code_append("\x48\x89\xfb"); // mov rbx, rdi

	for (size_t i = 0; i < cvector_size(instrs); i++) {
		Instr instr = instrs[i];

		switch (instr.op) {
		case OP_MOVE:
			if (instr.arg == 1)
				code_append("\x48\xff\xc3"); // inc rbx
			else if (instr.arg == -1)
				code_append("\x48\xff\xcb"); // dec rbx
			else if (instr.arg > 0) {
				assert(instr.arg <= UCHAR_MAX);
				code_append("\x48\x83\xc3"); // add rbx, imm8
				cvector_push_back(code, instr.arg);
			} else if (instr.arg < 0) {
				assert(-instr.arg <= UCHAR_MAX);
				code_append("\x48\x83\xeb"); // sub rbx, imm8
				cvector_push_back(code, -instr.arg);
			}

			break;
		case OP_ADD:
			if (instr.arg == 1)
				code_append("\xfe\x03"); // inc BYTE PTR [rbx]
			else if (instr.arg == -1)
				code_append("\xfe\x0b"); // dec BYTE PTR [rbx]
			else if (instr.arg > 0) {
				assert(instr.arg <= UCHAR_MAX);
				code_append("\x80\x03"); // add BYTE PTR [rbx], imm8
				cvector_push_back(code, instr.arg);
			} else if (instr.arg < 0) {
				assert(-instr.arg <= UCHAR_MAX);
				code_append("\x80\x2b"); // sub BYTE PTR [rbx], imm8
				cvector_push_back(code, -instr.arg);
			}

			break;
		case OP_OUTPUT: {
			const char snip[] = "\x48\x0f\xbe\x3b"      // movsx rdi, BYTE PTR [rbx]
								"\xe8\x00\x00\x00\x00"; // call  rel32

			cvector_push_back(putcharpatches, cvector_size(code) + 5);
			code_append(snip);
			break;
		}
		case OP_INPUT: {
			const char snip[] = "\xe8\x00\x00\x00\x00" // call rel32
								"\x88\x03";            // mov  BYTE PTR [rbx], al

			cvector_push_back(getcharpatches, cvector_size(code) + 1);
			code_append(snip);
			break;
		}
		case OP_JUMP_RIGHT: {
			const char snip[] = "\x80\x3b\x00"      // cmp BYTE PTR [rbx], 0
								"\x0f\x84"          // jz rel32
								"\x90\x90\x90\x90"; // 4x nop

			code_append(snip);
			cvector_push_back(jmps, cvector_size(code));
			break;
		}
		case OP_JUMP_LEFT: {
			code_append("\x80\x3b\x00"); // cmp BYTE PTR [rbx], 0

			size_t jmp = jmps[cvector_size(jmps) - 1];
			cvector_pop_back(jmps);

			{
				int rel = jmp - (cvector_size(code) + 2);

				if (rel >= CHAR_MIN && rel <= CHAR_MAX) {
					code_append("\x75"); // jnz rel8
					cvector_push_back(code, rel);
				} else {
					code_append("\x0f\x85"); // jnz rel32

					const char relbytes[5];
					*(int *)relbytes = rel - 4;
					code_append(relbytes);
				}
			}

			{
				int rel = cvector_size(code) - jmp;

				if (rel >= CHAR_MIN && rel <= CHAR_MAX) {
					code[jmp - 6] = 0x74; // jz rel8
					code[jmp - 5] = rel + 4;
				} else {
					*(int *)(code + jmp - 4) = rel; // rel32
				}
			}

			break;
		}
		case OP_CLEAR:
			code_append("\xc6\x03\x00"); // mov BYTE PTR [rbx], 0
			break;
		case OP_ADD_TO: {
			const char snip[] = "\x8a\x03"      // mov al, BYTE PTR [rbx]
								"\x00\x43\x00"  // add BYTE PTR [rbx + n], al
								"\xc6\x03\x00"; // mov BYTE PTR [rbx], 0

			code_append(snip);
			code[cvector_size(code) - 4] = instr.arg;
			break;
		}
		case OP_MOVE_UNTIL:
			if (instr.arg == 1) {
				const char snip[] = "\x80\x3b\x00" // cmp BYTE PTR [rbx], 0
									"\x74\x05"     // je +5
									"\x48\xff\xc3" // inc rbx
									"\xeb\xf6";    // jmp -10

				code_append(snip);
			} else if (instr.arg == -1) {
				const char snip[] = "\x80\x3b\x00" // cmp BYTE PTR [rbx], 0
									"\x74\x05"     // je +5
									"\x48\xff\xcb" // dec rbx
									"\xeb\xf6";    // jmp -10

				code_append(snip);
			} else if (instr.arg > 1) {
				const char snip[] = "\x80\x3b\x00"     // cmp BYTE PTR [rbx], 0
									"\x74\x06"         // je +6
									"\x48\x83\xc3\x00" // add rbx, imm8
									"\xeb\xf5";        // jmp -11

				code_append(snip);
				code[cvector_size(code) - 3] = instr.arg;
			} else if (instr.arg < 1) {
				const char snip[] = "\x80\x3b\x00"     // cmp BYTE PTR [rbx], 0
									"\x74\x06"         // je +6
									"\x48\x83\xeb\x00" // sub rbx, imm8
									"\xeb\xf5";        // jmp -11

				code_append(snip);
				code[cvector_size(code) - 3] = -instr.arg;
			}

			break;
		}
	}

	cvector_free(instrs);
	cvector_free(jmps);

	code_append("\xc3"); // ret

	void *fn = mmap(NULL, cvector_size(code), PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!fn)
		die("could not allocate executable memory:");

	for (size_t i = 0; i < cvector_size(putcharpatches); i++)
		*(int *)&code[putcharpatches[i]] = (uintptr_t)putchar_unlocked - ((uintptr_t)fn + putcharpatches[i] + 4);

	cvector_free(putcharpatches);

	for (size_t i = 0; i < cvector_size(getcharpatches); i++)
		*(int *)&code[getcharpatches[i]] = (uintptr_t)getchar_unlocked - ((uintptr_t)fn + getcharpatches[i] + 4);

	cvector_free(getcharpatches);

#ifdef PRINT_BUT_DONT_EXEC
	fwrite(code, cvector_size(code), 1, stdout);

	return 0;
#endif

	memcpy(fn, code, cvector_size(code));
	mprotect(fn, cvector_size(code), PROT_EXEC);
	cvector_free(code);

	size_t tapesize     = 30000;
	size_t pagesize     = getpagesize();
	size_t realtapesize = (tapesize + pagesize - 1) & ~(pagesize - 1);

	char *tape          = mmap(NULL, realtapesize + pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!tape)
		die("could not allocate tape memory:");

	tapeguardpage = tape + realtapesize;
	if (mprotect(tapeguardpage, pagesize, PROT_NONE) < 0)
		die("could not protect tape memory guard page:");

	struct sigaction sa;
	sa.sa_sigaction = handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSEGV, &sa, NULL) < 0)
		die("could not prepare tape memory guard page:");

	(*(void (**)(void *))&fn)(tape);
	// leak tape on purpose

	return 0;
}
