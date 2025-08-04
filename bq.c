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
#include <fcntl.h>
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
#include <sys/ucontext.h>
#include <unistd.h>

#define cvector_clib_malloc emalloc
#define cvector_clib_realloc erealloc
#include "cvector.h"

//#define PRINT_BUT_DONT_EXEC

#define code_trap() code_append("\xcc")

#define likely(x) (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))
#define likeliness(x, l) (__builtin_expect_with_probability(!!(x), 0, l))

static char  *tape, *tapeguardpages[2];
static size_t realtapesize;

typedef enum { OP_MOVE, OP_ADD, OP_OUTPUT, OP_INPUT, OP_JUMP_RIGHT, OP_JUMP_LEFT, OP_CLEAR, OP_ADD_TO, OP_MOVE_UNTIL } Opcode;

typedef struct {
	Opcode op;
	int    arg;
} Instr;

static inline size_t
max(size_t a, size_t b)
{
	return a > b ? a : b;
}

static void
usage(char *argv0)
{
	fprintf(stderr, "usage: %s [file]\n", argv0);
	exit(1);
}

__attribute((noreturn)) static void
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

	if unlikely (!(p = malloc(size)))
		die("emalloc:");

	return p;
}

static void *
erealloc(void *ptr, size_t size)
{
	void *p;

	if unlikely (!(p = realloc(ptr, size)))
		die("erealloc:");

	return p;
}

static bool
isop(char c)
{
	return strchr("><+-.,[]", c);
}

static void
handler(int signum, siginfo_t *si, void *ucontext)
{
	(void)signum;

	size_t pagesize = getpagesize();

	if likely (si->si_addr >= (void *)tapeguardpages[1] && si->si_addr < (void *)(tapeguardpages[1] + pagesize)) {
		munmap(tapeguardpages[0], pagesize);
		munmap(tapeguardpages[1], pagesize);

		char *oldtape = tape;
		tape          = (char *)mremap(tape, realtapesize, realtapesize * 2 + pagesize * 2, MREMAP_MAYMOVE);
		if (tape == MAP_FAILED)
			die("could not resize tape memory:");

		tape += pagesize;
		realtapesize *= 2;

		if likely (tape != oldtape) {
			ucontext_t *uctx                 = ucontext;
			uctx->uc_mcontext.gregs[REG_RBX] = (greg_t)tape + uctx->uc_mcontext.gregs[REG_RBX] - (uintptr_t)oldtape;
		}

		tapeguardpages[1] = tape + realtapesize;
		if unlikely (mprotect(tapeguardpages[1], pagesize, PROT_NONE) < 0)
			die("could not protect tape memory overflow guard page:");

		tapeguardpages[0] = tape - pagesize;
		if unlikely (mprotect(tapeguardpages[0], pagesize, PROT_NONE) < 0)
			die("could not protect tape memory underflow guard page:");

		return;
	}

	if likely (si->si_addr >= (void *)tapeguardpages[0] && si->si_addr < (void *)(tapeguardpages[0] + getpagesize()))
		die("tape memory underflow detected");

	SIG_DFL(signum);
	__builtin_unreachable();
}

int
main(int argc, char *argv[])
{
	if unlikely (argc != 2)
		usage(argv[0]);

	int fd = open(argv[1], O_RDONLY);
	if unlikely (fd < 0)
		die("cannot access '%s':", argv[1]);

	struct stat st;
	fstat(fd, &st);

	char *txt = emalloc(st.st_size);
	read(fd, txt, st.st_size);
	close(fd);

	cvector(Instr) instrs = NULL;
	cvector_reserve(instrs, (size_t)st.st_size);

	for (char *s = txt; likely(*s); s++) {
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

			if likely (n != 0) {
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

			if likely (n != 0) {
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

	cvector(unsigned char) code = NULL;
	cvector_reserve(code, max(cvector_size(instrs) * 5, 128));

	cvector(uintptr_t) jmps = NULL;
	cvector_reserve(jmps, max(cvector_size(instrs) / 20, 16));

	cvector(uintptr_t) overflowpatches = NULL;
	cvector_reserve(overflowpatches, max(cvector_size(instrs) / 100, 64));

	cvector(uintptr_t) uflowpatches = NULL;
	cvector_reserve(uflowpatches, max(cvector_size(instrs) / 200, 32));

#define code_append(snip_)                                       \
	do {                                                         \
		size_t snip_size_ = sizeof snip_ / sizeof *snip_ - 1;    \
		cvector_reserve(code, cvector_size(code) + snip_size_);  \
		memcpy(code + cvector_size(code), snip_, snip_size_);    \
		cvector_set_size(code, cvector_size(code) + snip_size_); \
	} while (0)

	const char snip[] = "\x49\xbd\x00\x00\x00\x00\x00\x00\x00\x00" // movabs r13, imm64
						"\x49\xbe\x00\x00\x00\x00\x00\x00\x00\x00" // movabs r14, imm64
						"\x48\x89\xfb";                            // mov rbx, rdi

	code_append(snip);
	*(void **)(code + cvector_size(code) - 21) = stdin;
	*(void **)(code + cvector_size(code) - 11) = stdout;

	for (size_t i = 0; likely(i < cvector_size(instrs)); i++) {
		Instr instr = instrs[i];

		switch (instr.op) {
		case OP_MOVE:
			if (instr.arg == 1)
				code_append("\x48\xff\xc3"); // inc rbx
			else if (instr.arg == -1)
				code_append("\x48\xff\xcb"); // dec rbx
			else if (instr.arg > 0) {
				unsigned int n = instr.arg;

				if likely (n <= UCHAR_MAX) {
					code_append("\x48\x83\xc3\x00"); // add rbx, imm8
					code[cvector_size(code) - 1] = n;
				} else {
					code_append("\x48\x81\xc3\x00\x00\x00\x00"); // add rbx, imm32
					*(unsigned int *)(code + cvector_size(code) - 4) = n;
				}
			} else if (instr.arg < 0) {
				unsigned int n = -instr.arg;

				if (n <= UCHAR_MAX) {
					code_append("\x48\x83\xeb\x00"); // sub rbx, imm8
					code[cvector_size(code) - 1] = n;
				} else {
					code_append("\x48\x81\xeb\x00\x00\x00\x00"); // sub rbx, imm32
					*(unsigned int *)(code + cvector_size(code) - 4) = n;
				}
			}
			break;
		case OP_ADD: {
			short n = instr.arg % 256;

			if (n == 1)
				code_append("\xfe\x03"); // inc BYTE PTR [rbx]
			else if (n == -1)
				code_append("\xfe\x0b"); // dec BYTE PTR [rbx]
			else if (n > 0) {
				code_append("\x80\x03\x00"); // add BYTE PTR [rbx], imm8
				code[cvector_size(code) - 1] = n;
			} else if (n < 0) {
				code_append("\x80\x2b\x00"); // sub BYTE PTR [rbx], imm8
				code[cvector_size(code) - 1] = -n;
			}

			break;
		}
		case OP_OUTPUT: {
			const char snip[] = "\x40\x8a\x33"         // mov   sil, BYTE PTR [rbx]
								"\x49\x8b\x46\x28"     // mov   rax, QWORD PTR [r14 + 0x28]
								"\x49\x3b\x46\x20"     // cmp   rax, QWORD PTR [r14 + 0x20]
								"\x75\x0e"             // jne   +14
								"\x4c\x89\xf7"         // mov   rdi, r14
								"\x40\x0f\xbe\xf6"     // movsx esi, sil
								"\xe8\x00\x00\x00\x00" // call  rel32
								"\xeb\x0b"             // jmp   +11
								"\x48\x8d\x50\x01"     // lea   rdx, [rax + 0x1]
								"\x49\x89\x56\x28"     // mov   QWORD PTR [r14 + 0x28], rdx
								"\x40\x88\x30";        // mov   BYTE PTR [rax], sil

			cvector_push_back(overflowpatches, cvector_size(code) + 21);
			code_append(snip);
			break;
		}
		case OP_INPUT: {
			const char snip[] = "\x49\x8b\x45\x08"     // mov  rax, QWORD PTR [r13 + 0x8]
								"\x49\x3b\x45\x10"     // cmp  rax, QWORD PTR [r13 + 0x10]
								"\x75\x0a"             // jne  +10
								"\x4c\x89\xef"         // mov  rdi, r13
								"\xe8\x00\x00\x00\x00" // call rel32
								"\xeb\x0a"             // jmp  +10
								"\x48\x8d\x50\x01"     // lea  rdx, [rax + 0x1]
								"\x49\x89\x55\x08"     // mov  QWORD PTR [r13 + 0x8], rdx
								"\x8a\x00"             // mov  al, BYTE PTR [rax]
								"\x88\x03";            // mov  BYTE PTR [rbx], al

			cvector_push_back(uflowpatches, cvector_size(code) + 14);
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

			if unlikely (cvector_size(jmps) == 0)
				die("mismatched ]");

			size_t jmp = jmps[cvector_size(jmps) - 1];
			cvector_pop_back(jmps);

			{
				int rel = jmp - (cvector_size(code) + 2);

				if likely (rel >= CHAR_MIN && rel <= CHAR_MAX) {
					code_append("\x75\x00"); // jnz rel8
					code[cvector_size(code) - 1] = rel;
				} else {
					code_append("\x0f\x85\x00\x00\x00\x00"); // jnz rel32
					*(int *)(code + cvector_size(code) - 4) = rel - 4;
				}
			}

			{
				int rel = cvector_size(code) - jmp;

				if likely (rel >= CHAR_MIN && rel <= CHAR_MAX) {
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
			if likely (instr.arg >= CHAR_MIN && instr.arg <= CHAR_MAX) {
				const char snip[] = "\x8a\x03"      // mov al, BYTE PTR [rbx]
									"\x00\x43\x00"  // add BYTE PTR [rbx + disp8], al
									"\xc6\x03\x00"; // mov BYTE PTR [rbx], 0

				code_append(snip);
				code[cvector_size(code) - 4] = instr.arg;
			} else {
				const char snip[] = "\x8a\x03"                 // mov al, BYTE PTR [rbx]
									"\x00\x83\x00\x00\x00\x00" // add BYTE PTR [rbx + disp32], al
									"\xc6\x03\x00";            // mov BYTE PTR [rbx], 0

				code_append(snip);
				*(int *)(code + cvector_size(code) - 7) = instr.arg;
			}
			break;
		}
		case OP_MOVE_UNTIL:
			if (instr.arg == 1) {
				const char snip[] = "\x80\x3b\x00" // cmp BYTE PTR [rbx], 0
									"\x74\x05"     // je   5
									"\x48\xff\xc3" // inc rbx
									"\xeb\xf6";    // jmp -10

				code_append(snip);
			} else if (instr.arg == -1) {
				const char snip[] = "\x80\x3b\x00" // cmp BYTE PTR [rbx], 0
									"\x74\x05"     // je  +5
									"\x48\xff\xcb" // dec rbx
									"\xeb\xf6";    // jmp -10

				code_append(snip);
			} else if (instr.arg > 1) {
				unsigned int n = instr.arg;

				if likely (n <= UCHAR_MAX) {
					const char snip[] = "\x80\x3b\x00"     // cmp BYTE PTR [rbx], 0
										"\x74\x06"         // je  +6
										"\x48\x83\xc3\x00" // add rbx, imm8
										"\xeb\xf5";        // jmp -11

					code_append(snip);
					code[cvector_size(code) - 3] = n;
				} else {
					const char snip[] = "\x80\x3b\x00"                 // cmp BYTE PTR [rbx], 0
										"\x74\x09"                     // je  +9
										"\x48\x81\xc3\x00\x00\x00\x00" // add rbx, imm32
										"\xeb\xf2";                    // jmp -14

					code_append(snip);
					*(unsigned int *)(code + cvector_size(code) - 6) = n;
				}
			} else if (instr.arg < -1) {
				unsigned int n = -instr.arg;

				if likely (n <= UCHAR_MAX) {
					const char snip[] = "\x80\x3b\x00"     // cmp BYTE PTR [rbx], 0
										"\x74\x06"         // je  +6
										"\x48\x83\xeb\x00" // sub rbx, imm8
										"\xeb\xf5";        // jmp -11

					code_append(snip);
					code[cvector_size(code) - 3] = n;
				} else {
					const char snip[] = "\x80\x3b\x00"                 // cmp BYTE PTR [rbx], 0
										"\x74\x09"                     // je  +9
										"\x48\x81\xeb\x00\x00\x00\x00" // sub rbx, imm32
										"\xeb\xf2";                    // jmp -14

					code_append(snip);
					*(unsigned int *)(code + cvector_size(code) - 6) = n;
				}
			}
			break;
		}
	}

	if unlikely (cvector_size(jmps) != 0)
		die("unterminated [");

	cvector_free(instrs);
	cvector_free(jmps);

	code_append("\xc3"); // ret

	void *fn = mmap(NULL, cvector_size(code), PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if unlikely (!fn)
		die("could not allocate executable memory:");

	extern int __overflow(FILE *, int);
	for (size_t i = 0; i < cvector_size(overflowpatches); i++)
		*(int *)&code[overflowpatches[i]] = (uintptr_t)__overflow - ((uintptr_t)fn + overflowpatches[i] + 4);

	cvector_free(overflowpatches);

	extern int __uflow(FILE *);
	for (size_t i = 0; i < cvector_size(uflowpatches); i++)
		*(int *)&code[uflowpatches[i]] = (uintptr_t)__uflow - ((uintptr_t)fn + uflowpatches[i] + 4);

	cvector_free(uflowpatches);

#ifdef PRINT_BUT_DONT_EXEC
	fwrite(code, cvector_size(code), 1, stdout);

	return 0;
#endif

	memcpy(fn, code, cvector_size(code));
	mprotect(fn, cvector_size(code), PROT_EXEC);
	cvector_free(code);

	size_t tapesize = 30000;
	size_t pagesize = getpagesize();
	realtapesize    = (tapesize + pagesize - 1) & ~(pagesize - 1);

	tape            = mmap(NULL, realtapesize + pagesize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if unlikely (!tape)
		die("could not allocate tape memory:");

	tape += pagesize;

	tapeguardpages[1] = tape + realtapesize;
	if unlikely (mprotect(tapeguardpages[1], pagesize, PROT_NONE) < 0)
		die("could not protect tape memory overflow guard page:");

	tapeguardpages[0] = tape - pagesize;
	if unlikely (mprotect(tapeguardpages[0], pagesize, PROT_NONE) < 0)
		die("could not protect tape memory underflow guard page:");

	struct sigaction sa;
	sa.sa_sigaction = handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	if unlikely (sigaction(SIGSEGV, &sa, NULL) < 0)
		die("could not prepare tape memory guard page:");

	(*(void (**)(void *))&fn)(tape);
	// leak tape on purpose

	return 0;
}
