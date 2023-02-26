#include <stdio.h>
#include <string.h>
//#include <stdlib.h>

#include "asm.h"
#include "err/err.h"
#include "keystone/keystone.h"
#include "asmsplit/asmsplit.h"

#define STR_ERR(str) "%s", (str)

#define KEYSTONE_ERR_QUIT(...) err_quit("Keystone: " __VA_ARGS__)

#define STR_ASM "asm: "
#define ASM_ERR_QUIT(...) err_quit(STR_ASM __VA_ARGS__)
#define ASM_ERR_PRINT(...) err_print(STR_ASM __VA_ARGS__)

#define ARR_SIZE(arr_name) (sizeof(arr_name)/sizeof(*arr_name))

static struct {
	ks_engine * handle;
	ks_arch arch;
	ks_mode mode;
	ks_opt_value syntax;
	size_t curr_addr;
	size_t asm_calls;
	char * one_instr_buff;
	size_t oib_len;
} module;

typedef struct arch_descr {
	char arch[16];
	char details[64];
	ks_arch arch_id;
} arch_descr;
static const arch_descr ks_archs[] = {
{"arm", "ARM architecture (including Thumb, Thumb-2)", KS_ARCH_ARM},
{"arm64", "ARM-64, also called AArch64", KS_ARCH_ARM64},
{"mips", "Mips architecture", KS_ARCH_MIPS},
{"x86", "X86 architecture (including x86 & x86-64)", KS_ARCH_X86},
{"ppc", "PowerPC architecture (currently unsupported)", KS_ARCH_PPC},
{"sparc", "Sparc architecture", KS_ARCH_SPARC},
{"systemz", "SystemZ architecture (S390X)", KS_ARCH_SYSTEMZ},
{"hexagon", "Hexagon architecture", KS_ARCH_HEXAGON},
{"evm", "Ethereum Virtual Machine architecture", KS_ARCH_EVM},
};

typedef struct mode_descr {
	char mode[16];
	char details[64];
	ks_mode mode_id;
} mode_descr;
static const mode_descr ks_modes[] = {
{"little_endian", "little-endian mode (default mode)", KS_MODE_LITTLE_ENDIAN},
{"big_endian", "big-endian mode", KS_MODE_BIG_ENDIAN},
{"arm", "ARM mode", KS_MODE_ARM},
{"thumb", "ARM THUMB mode (including Thumb-2)", KS_MODE_THUMB},
{"v8", "ARMv8 A32 encodings for ARM", KS_MODE_V8},
{"micro", "MicroMips mode", KS_MODE_MICRO},
{"mips3", "Mips III ISA", KS_MODE_MIPS3},
{"mips32r6", "Mips32r6 ISA", KS_MODE_MIPS32R6},
{"mips32", "Mips32 ISA", KS_MODE_MIPS32},
{"mips64", "Mips64 ISA", KS_MODE_MIPS64},
{"16", "x86 16-bit mode", KS_MODE_16},
{"32", "x86 32-bit mode", KS_MODE_32},
{"64", "x86 64-bit mode", KS_MODE_64},
{"ppc32", "PPC 32-bit mode", KS_MODE_PPC32},
{"ppc64", "PPC 64-bit mode", KS_MODE_PPC64},
{"qpx", "PPC Quad Processing eXtensions mode", KS_MODE_QPX},
{"sparc32", "SPARC 32-bit mode", KS_MODE_SPARC32},
{"sparc64", "SPARC 64-bit mode", KS_MODE_SPARC64},
{"v9", "SPARC SparcV9 mode", KS_MODE_V9},
};

typedef struct syntax_descr {
	char sntx[16];
	char details[64];
	ks_opt_value sntx_id;
} syntax_descr;
static const syntax_descr ks_sntxs[] = {
{"intel", "X86 Intel syntax - default on X86 (KS_OPT_SYNTAX).", KS_OPT_SYNTAX_INTEL},
{"att", "X86 ATT asm syntax (KS_OPT_SYNTAX).", KS_OPT_SYNTAX_ATT  },
{"nasm", "X86 Nasm syntax (KS_OPT_SYNTAX).", KS_OPT_SYNTAX_NASM },
{"masm", "X86 Masm syntax (KS_OPT_SYNTAX) - unsupported yet.", KS_OPT_SYNTAX_MASM },
{"gas", "X86 GNU GAS syntax (KS_OPT_SYNTAX).", KS_OPT_SYNTAX_GAS  },
{"radix16", "All immediates are in hex format (i.e 12 is 0x12)", KS_OPT_SYNTAX_RADIX16},
};

#define ARCH_FMT "%-13s - %s\n"

void asm_print_options(void)
{
#define ASM_PRINT_OPTS_LOOP(str, id)                                           \
puts("\n" str);                                                                \
for (size_t i = 0; i < ARR_SIZE(ks_ ## id ## s); ++i)                          \
	printf(ARCH_FMT, ks_ ## id ## s [i]. id, ks_ ## id ## s [i].details);

	ASM_PRINT_OPTS_LOOP("Assembly architectures possible:", arch);
	ASM_PRINT_OPTS_LOOP("Assembly modes:", mode);
	ASM_PRINT_OPTS_LOOP("Assembly syntaxes:", sntx);
	
	puts("");
	asm_print_arch();
#undef ASM_PRINT_OPTS_LOOP
}

void asm_print_arch(void)
{
	puts("Assembly architectures compiled in:");
	for (size_t i = 0; i < ARR_SIZE(ks_archs); ++i)
	{
		if (ks_arch_supported(ks_archs[i].arch_id))
			printf(ARCH_FMT, ks_archs[i].arch, ks_archs[i].details);
	}
}

#define ASM_GET_OPT(id, farg, err_str, ret)           \
for (size_t i = 0; i < ARR_SIZE(ks_ ## id ## s); ++i) \
{                                                     \
	if (strcmp(farg, ks_ ## id ## s[i]. id) == 0)     \
		return ks_ ## id ## s[i]. id ## _id;          \
}                                                     \
ASM_ERR_QUIT(err_str, farg);                          \
return ret; // never reached

static ks_arch get_arch(const char * arch)
{
ASM_GET_OPT(arch, arch, "'%s' not a valid architecture", KS_ARCH_MAX);
}

static ks_mode get_mode(const char * mode)
{
ASM_GET_OPT(mode, mode, "'%s' not a valid mode", KS_MODE_LITTLE_ENDIAN);
}

static ks_opt_value get_syntax(const char * syntax)
{
ASM_GET_OPT(sntx, syntax, "'%s' not a valid syntax", KS_OPT_SYNTAX_RADIX16);
}
#undef ASM_GET_OPT

void asm_get_ks_version(unsigned int * major, unsigned int * minor)
{
	ks_version(major, minor);
}

void asm_init(
	const char * arch,
	const char * mode,
	const char * syntax,
	size_t start_addr,
	size_t max_single_instr_len
)
{
	module.asm_calls = 0;
	module.arch = (arch) ? get_arch(arch) : KS_ARCH_X86;	
	module.mode = (mode) ? get_mode(mode) : KS_MODE_64;
	module.syntax = (syntax) ? get_syntax(syntax) : KS_OPT_SYNTAX_INTEL;
	
	module.oib_len = max_single_instr_len;
	module.one_instr_buff = (char *)calloc(1, module.oib_len);
	if (!module.one_instr_buff)
		ASM_ERR_QUIT("calloc(1, %zu) failed in asm_init()", module.oib_len);
	
	if (!ks_arch_supported(module.arch))
		KEYSTONE_ERR_QUIT("architecture '%s' not available", arch); 
	
	module.curr_addr = start_addr;
	
	ks_err err = ks_open(module.arch, module.mode, &module.handle);
	if (err != KS_ERR_OK)
		KEYSTONE_ERR_QUIT(STR_ERR(ks_strerror(err)));
	
	if (syntax)
	{
		err = ks_option(module.handle, KS_OPT_SYNTAX, module.syntax);
		if (err != KS_ERR_OK)
			KEYSTONE_ERR_QUIT("syntax '%s' not available", ks_strerror(err));
	}
}

void asm_asm(FILE * where, const char * asm_str)
{
	++module.asm_calls;
	
	size_t instr_num = 0;
	size_t out_count = 0;
	size_t out_size = 0;
	const char * err = NULL;
	const char * pinstr = asm_str;
	unsigned char * encode = NULL;
	while ((pinstr = asm_instr_next(pinstr,
		module.one_instr_buff, module.oib_len, &err)))
	{
		++instr_num;
		if (KS_ERR_OK == ks_asm(module.handle,
			module.one_instr_buff, module.curr_addr, &encode,
				&out_size, &out_count))
		{
			fprintf(where, "0x%04jx | ", module.curr_addr);
			for (size_t i = 0; i < out_size; ++i)
				fprintf(where, "%02x ", encode[i]);
			fprintf(where, "| %s\n", module.one_instr_buff);
			module.curr_addr += out_size;

			ks_free(encode);
		}
		else
		{
			ASM_ERR_PRINT("bad instruction syntax");
				
			err_out("string %d: '%s'\n", module.asm_calls, asm_str);
			err_out("instruction %d: '%s'\n", instr_num, module.one_instr_buff);
			
			KEYSTONE_ERR_QUIT(STR_ERR(ks_strerror(ks_errno(module.handle))));
		}
	}
	
	if (err)
		ASM_ERR_QUIT("%s; size was %zu", err, module.oib_len);
}

void asm_close(void)
{
	free(module.one_instr_buff);
	ks_close(module.handle);
}
