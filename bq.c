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
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ucontext.h>
#include <unistd.h>

static void *emalloc(size_t size);
static void *erealloc(void *ptr, size_t size);
#define DA_ALLOC emalloc
#define DA_REALLOC erealloc
#define DA_IMPLEMENTATION
#include "da.h"

// #define PRINT_BUT_DONT_EXEC

#define code_trap() code_append("\xcc")

#define likely(x) (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))
#define likeliness(x, l) (__builtin_expect_with_probability(!!(x), 0, l))
#define hot __attribute((hot))
#define cold __attribute((cold))
#define noreturn __attribute((noreturn))

static char  *tape, *tapestart, *tapeguardpages[2];
static size_t realtapesize;

typedef enum {
	OP_INVALID,
	OP_MOVE,
	OP_ADD,
	OP_OUTPUT,
	OP_INPUT,
	OP_JUMP_RIGHT,
	OP_JUMP_LEFT,
	OP_CLEAR,
	OP_ADD_TO,
	OP_MOVE_UNTIL
} Opcode;

static const char *const nops[] = {
	"\x90",                                    // nop
	"\x66\x90",                                // xchg ax,ax
	"\x0f\x1f\x00",                            // nop DWORD PTR [eax]
	"\x0f\x1f\x40\x00",                        // nop DWORD PTR [eax+0x0]
	"\x0f\x1f\x44\x00\x00",                    // nop DWORD PTR [eax+eax*1+0x0]
	"\x66\x0f\x1f\x44\x00\x00",                // nop WORD PTR [eax+eax*1+0x0]
	"\x0f\x1f\x80\x00\x00\x00\x00",            // nop DWORD PTR [eax+0x0]
	"\x0f\x1f\x84\x00\x00\x00\x00\x00",        // nop DWORD PTR [eax+eax*1+0x0]
	"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",    // nop WORD PTR [eax+eax*1+0x0]
	"\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00" // nop WORD PTR cs:[eax+eax*1+0x0]
};

typedef struct {
	Opcode op;
	int    arg;
} Instr;

typedef struct {
	da_fields(Instr);
} Instrs;

typedef struct {
	da_fields(uintptr_t);
} UintPtrs;

static inline size_t
max(size_t a, size_t b)
{
	return a > b ? a : b;
}

static void cold
usage(char *argv0)
{
	fprintf(stderr, "usage: %s [file]\n", argv0);
	exit(1);
}

static void noreturn cold
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

static bool hot
isop(char c)
{
	return strchr("><+-.,[]", c);
}

static bool
isstdincomplete(struct stat *st)
{
	if (isatty(STDIN_FILENO))
		return false;

	if (fstat(STDIN_FILENO, st) < 0)
		return false;

	if (S_ISREG(st->st_mode))
		return true;

	if (S_ISFIFO(st->st_mode)) {
		struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
		poll(&pfd, 1, 0);
		return pfd.revents & POLLHUP;
	}

	return false;
}

static void
handler(int signum, siginfo_t *si, void *ucontext)
{
	size_t pagesize = getpagesize();
	void  *addr     = si->si_addr;

	if unlikely (!(((addr >= (void *)tapeguardpages[1]) && (addr < (void *)(tapeguardpages[1] + pagesize))) ||
	               ((addr >= (void *)tapeguardpages[0]) && (addr < (void *)(tapeguardpages[0] + pagesize))))) {
		SIG_DFL(signum);
		__builtin_unreachable();
	}

	munmap(tapeguardpages[0], pagesize);
	munmap(tapeguardpages[1], pagesize);

	char *oldtapestart = tapestart;
	char *newtapestart = (char *)mremap(tapestart, realtapesize + pagesize * 2, realtapesize * 2 + pagesize * 2, MREMAP_MAYMOVE);
	if (newtapestart == MAP_FAILED)
		die("could not resize tape memory:");

	tapestart = newtapestart;
	tape      = tapestart + pagesize + realtapesize / 2;
	realtapesize *= 2;

	if likely (tapestart != oldtapestart) {
		ucontext_t *uctx = ucontext;
		uctx->uc_mcontext.gregs[REG_RBX] =
				(greg_t)tape + uctx->uc_mcontext.gregs[REG_RBX] - (uintptr_t)(oldtapestart + pagesize + realtapesize / 4);
	}

	tapeguardpages[1] = tapestart + realtapesize + pagesize;
	if unlikely (mprotect(tapeguardpages[1], pagesize, PROT_NONE) < 0)
		die("could not protect tape memory overflow guard page:");

	tapeguardpages[0] = tapestart;
	if unlikely (mprotect(tapeguardpages[0], pagesize, PROT_NONE) < 0)
		die("could not protect tape memory underflow guard page:");
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

	struct stat stdin_st;
	bool        stdin_complete = isstdincomplete(&stdin_st);
	char       *stdin_txt      = NULL;

	if (stdin_complete) {
		if (S_ISREG(stdin_st.st_mode)) {
			stdin_txt = emalloc(stdin_st.st_size);
			read(STDIN_FILENO, stdin_txt, stdin_st.st_size);
		} else if (S_ISFIFO(stdin_st.st_mode)) {
			int n;
			ioctl(STDIN_FILENO, FIONREAD, &n);
			stdin_txt = emalloc(n + 1);
			read(STDIN_FILENO, stdin_txt, n);
			stdin_txt[n] = '\0';
		} else {
			stdin_complete = false;
		}
	}

	Instrs instrs = { 0 };
	for (char *s = txt; likely(*s); s++) {
		Instr instr = { 0 };
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
				da_append(&instrs, instr);
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
				da_append(&instrs, instr);
			}

			break;
		}
		case '.':
			instr.op = OP_OUTPUT;
			da_append(&instrs, instr);
			break;
		case ',':
			instr.op = OP_INPUT;
			da_append(&instrs, instr);
			break;
		case '[':
			instr.op = OP_JUMP_RIGHT;
			da_append(&instrs, instr);
			break;
		case ']': {
			size_t len = instrs.count;

			// [-] or [+]
			if (len >= 2 && instrs.items[len - 1].op == OP_ADD && instrs.items[len - 1].arg & 1 &&
			    instrs.items[len - 2].op == OP_JUMP_RIGHT) {
				instrs.count = len - 2;
				instr.op     = OP_CLEAR;
				da_append(&instrs, instr);
				break;
			}

			// [->+<] or [-<+>]
			if (len >= 5 && instrs.items[len - 1].op == OP_MOVE && instrs.items[len - 2].op == OP_ADD &&
			    instrs.items[len - 2].arg == 1 && instrs.items[len - 3].op == OP_MOVE && instrs.items[len - 4].op == OP_ADD &&
			    instrs.items[len - 4].arg == -1 && instrs.items[len - 1].arg == -instrs.items[len - 3].arg &&
			    instrs.items[len - 5].op == OP_JUMP_RIGHT) {
				instrs.count = len - 5;
				instr        = (Instr){ OP_ADD_TO, instrs.items[len - 3].arg };
				da_append(&instrs, instr);
				break;
			}

			// [>] or [<]
			if (len >= 2 && instrs.items[len - 1].op == OP_MOVE && instrs.items[len - 2].op == OP_JUMP_RIGHT) {
				instrs.count = len - 2;
				instr        = (Instr){ OP_MOVE_UNTIL, instrs.items[len - 1].arg };
				da_append(&instrs, instr);
				break;
			}

			instr.op = OP_JUMP_LEFT;
			da_append(&instrs, instr);
			break;
		}
		case OP_INVALID: __builtin_unreachable();
		default: break;
		}
	}

	free(txt);

	StringBuilder code = { 0 };
	da_reserve(&code, max(instrs.count * 5, DA_INIT_CAP));

	UintPtrs jmps = { 0 };
	da_reserve(&code, max(instrs.count / 20, 16));

	UintPtrs putcharpatches = { 0 };
	da_reserve(&code, max(instrs.count / 100, 64));

	UintPtrs getcharpatches = { 0 };
	da_reserve(&code, max(instrs.count / 200, 32));

#define code_append(snip_) da_append_many(&code, snip_, sizeof(snip_) / sizeof(*snip_) - 1)

#define code_align(align)                                                  \
	do {                                                                   \
		if (align <= 1)                                                    \
			break;                                                         \
		size_t    off = code.count;                                        \
		uintptr_t cur = (uintptr_t)(code.items + off);                     \
		size_t    pad = ((align) - (cur & ((align) - 1))) & ((align) - 1); \
		da_reserve(&code, off + pad);                                      \
		size_t i = 0;                                                      \
		while (pad > 0) {                                                  \
			size_t nopsize = pad > 10 ? 10 : pad;                          \
			memcpy(code.items + off + i, nops[nopsize - 1], nopsize);      \
			i += nopsize;                                                  \
			pad -= nopsize;                                                \
		}                                                                  \
		code.count = off + i;                                              \
	} while (0)

	if (stdin_complete) {
		code_append("\x49\xbf\x00\x00\x00\x00\x00\x00\x00\x00"); // movabs r15, imm64
		*(char **)da_at(&code, -8) = stdin_txt;
	}

	const char snip[] = "\x49\xbd\x00\x00\x00\x00\x00\x00\x00\x00" // movabs r13, imm64
						"\x49\xbe\x00\x00\x00\x00\x00\x00\x00\x00" // movabs r14, imm64
						"\x48\x89\xfb";                            // mov rbx, rdi

	code_append(snip);
	*(void **)da_at(&code, -21) = stdin;
	*(void **)da_at(&code, -11) = stdout;

	size_t icacheline           = sysconf(_SC_LEVEL1_ICACHE_LINESIZE);
	code_align(icacheline);

	for (size_t i = 0; likely(i < instrs.count); i++) {
		Instr instr = instrs.items[i];

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
					*da_at(&code, -1) = n;
				} else {
					code_append("\x48\x81\xc3\x00\x00\x00\x00"); // add rbx, imm32
					*da_at(&code, -4) = n;
				}
			} else if (instr.arg < 0) {
				unsigned int n = -instr.arg;

				if (n <= UCHAR_MAX) {
					code_append("\x48\x83\xeb\x00"); // sub rbx, imm8
					*da_at(&code, -1) = n;
				} else {
					code_append("\x48\x81\xeb\x00\x00\x00\x00"); // sub rbx, imm32
					*(unsigned int *)da_at(&code, -4) = n;
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
				*da_at(&code, -1) = n;
			} else if (n < 0) {
				code_append("\x80\x2b\x00"); // sub BYTE PTR [rbx], imm8
				*da_at(&code, -1) = -n;
			}

			break;
		}
		case OP_OUTPUT: {
			const char snip[] = "\x48\x0f\xbe\x3b"      // movsx rdi, BYTE PTR [rbx]
								"\xe8\x00\x00\x00\x00"; // call  rel32

			da_append(&putcharpatches, code.count + 5);
			code_append(snip);
			break;
		}
		case OP_INPUT: {
			if (!stdin_complete) {
				const char snip[] = "\xe8\x00\x00\x00\x00" // call rel32
									"\x88\x03";            // mov  BYTE PTR [rbx], al
				da_append(&getcharpatches, code.count + 1);
				code_append(snip);
			} else {
				const char snip[] = "\x41\x8a\07"   // mov al, BYTE PTR [r15]
									"\x88\x03"      // mov BYTE PTR [rbx], al
									"\x49\xff\xc7"; // inc r15
				code_append(snip);
			}
			break;
		}
		case OP_JUMP_RIGHT: {
			const char snip[] = "\x80\x3b\x00"      // cmp BYTE PTR [rbx], 0
								"\x0f\x84"          // jz rel32
								"\x0f\x1f\x40\x00"; // nop DWORD PTR [eax+0x0]

			size_t cost         = 0;
			size_t jmpstraverse = jmps.count + 1;
			for (size_t j = i; jmpstraverse && likely(j < instrs.count); j++)
				switch (instrs.items[j].op) {
				case OP_MOVE: cost += 3; break;
				case OP_ADD: cost += 1; break;
				case OP_OUTPUT: cost += 40; break;
				case OP_INPUT: cost += 35; break;
				case OP_JUMP_RIGHT: cost += 10; break;
				case OP_JUMP_LEFT:
					cost += 8;
					jmpstraverse--;
					break;
				case OP_CLEAR: cost += 2; break;
				case OP_ADD_TO: cost += 10; break;
				case OP_MOVE_UNTIL: cost += 10; break;
				case OP_INVALID: break;
				}

			code_align(icacheline >> ((jmps.count + 1) * cost / 50));
			code_append(snip);
			da_append(&jmps, code.count);
			break;
		}
		case OP_JUMP_LEFT: {
			code_append("\x80\x3b\x00"); // cmp BYTE PTR [rbx], 0

			if unlikely (jmps.count == 0)
				die("mismatched ]");

			size_t jmp = da_pop(&jmps);

			{
				int rel = jmp - (code.count + 2);

				if likely (rel >= CHAR_MIN && rel <= CHAR_MAX) {
					code_append("\x75\x00"); // jnz rel8
					*da_at(&code, -1) = rel;
				} else {
					code_append("\x0f\x85\x00\x00\x00\x00"); // jnz rel32
					*(int *)da_at(&code, -4) = rel - 4;
				}
			}

			{
				int rel = code.count - jmp;

				if likely (rel >= CHAR_MIN && rel <= CHAR_MAX) {
					code.items[jmp - 6] = 0x74; // jz rel8
					code.items[jmp - 5] = rel + 4;
				} else {
					*(int *)&code.items[jmp - 4] = rel; // rel32
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
				*da_at(&code, -4) = instr.arg;
			} else {
				const char snip[] = "\x8a\x03"                 // mov al, BYTE PTR [rbx]
									"\x00\x83\x00\x00\x00\x00" // add BYTE PTR [rbx + disp32], al
									"\xc6\x03\x00";            // mov BYTE PTR [rbx], 0

				code_append(snip);
				*(int *)da_at(&code, 7) = instr.arg;
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
					*da_at(&code, -3) = n;
				} else {
					const char snip[] = "\x80\x3b\x00"                 // cmp BYTE PTR [rbx], 0
										"\x74\x09"                     // je  +9
										"\x48\x81\xc3\x00\x00\x00\x00" // add rbx, imm32
										"\xeb\xf2";                    // jmp -14

					code_append(snip);
					*(unsigned int *)da_at(&code, -6) = n;
				}
			} else if (instr.arg < -1) {
				unsigned int n = -instr.arg;

				if likely (n <= UCHAR_MAX) {
					const char snip[] = "\x80\x3b\x00"     // cmp BYTE PTR [rbx], 0
										"\x74\x06"         // je  +6
										"\x48\x83\xeb\x00" // sub rbx, imm8
										"\xeb\xf5";        // jmp -11

					code_append(snip);
					*da_at(&code, -3) = n;
				} else {
					const char snip[] = "\x80\x3b\x00"                 // cmp BYTE PTR [rbx], 0
										"\x74\x09"                     // je  +9
										"\x48\x81\xeb\x00\x00\x00\x00" // sub rbx, imm32
										"\xeb\xf2";                    // jmp -14

					code_append(snip);
					*(unsigned int *)da_at(&code, -6) = n;
				}
			}
			break;
		case OP_INVALID: __builtin_unreachable();
		}
	}

	if unlikely (jmps.count != 0)
		die("unterminated [");

	da_free(&instrs);
	da_free(&jmps);

	code_append("\xc3"); // ret

	void *fn = mmap(NULL, code.count, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if unlikely (!fn)
		die("could not allocate executable memory:");

	for (size_t i = 0; i < putcharpatches.count; i++)
		*(int *)&code.items[putcharpatches.items[i]] =
				(uintptr_t)putchar_unlocked - ((uintptr_t)fn + putcharpatches.items[i] + 4);

	da_free(&putcharpatches);

	for (size_t i = 0; i < getcharpatches.count; i++)
		*(int *)&code.items[getcharpatches.items[i]] =
				(uintptr_t)getchar_unlocked - ((uintptr_t)fn + getcharpatches.items[i] + 4);

	da_free(&getcharpatches);

#ifdef PRINT_BUT_DONT_EXEC
	fwrite(code, code.count, 1, stdout);

	return 0;
#endif

	memcpy(fn, code.items, code.count);
	mprotect(fn, code.count, PROT_EXEC);
	da_free(&code);

	size_t tapesize = 30000;
	size_t pagesize = getpagesize();
	realtapesize    = (tapesize + pagesize - 1) & ~(pagesize - 1);

	tapestart       = mmap(NULL, realtapesize * 2 + pagesize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if unlikely (!tapestart)
		die("could not allocate tape memory:");

	tape              = tapestart + pagesize + realtapesize / 2;

	tapeguardpages[1] = tapestart + realtapesize + pagesize;
	if unlikely (mprotect(tapeguardpages[1], pagesize, PROT_NONE) < 0)
		die("could not protect tape memory overflow guard page:");

	tapeguardpages[0] = tapestart;
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
