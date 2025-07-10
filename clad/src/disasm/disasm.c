#include <ctype.h>
#include <string.h>

#include "disasm.h"
#include "err/err.h"

#define CAPSTONE_SYSTEMZ_COMPAT_HEADER
#define CAPSTONE_AARCH64_COMPAT_HEADER
#include "capstone/capstone.h"

#include "hex2bytes/hex2bytes.h"

#define STR_ERR(str) "%s", (str)

#define CAPSTONE_ERR_QUIT(...) err_quit("Capstone: " __VA_ARGS__)

#define STR_DISASM "disasm: "
#define DISASM_ERR_QUIT(...) err_quit(STR_DISASM __VA_ARGS__)
#define DISASM_ERR_PRINT(...) err_print(STR_DISASM __VA_ARGS__)

#define ARR_SIZE(arr_name) (sizeof(arr_name)/sizeof(*arr_name))

static struct {
	csh handle;
	cs_insn * inst;
	size_t curr_addr;
	cs_arch arch;
	cs_mode mode;
	cs_opt_value syntax;
	size_t disasm_calls;
} module;

typedef struct arch_descr {
	char arch[16];
	char details[64];
	cs_arch arch_id;
} arch_descr;
static const arch_descr cs_archs[] = {
{"arm", "ARM architecture (including Thumb, Thumb-2)", CS_ARCH_ARM},
{"arm64", "ARM-64, also called AArch64", CS_ARCH_ARM64},
{"mips", "Mips architecture", CS_ARCH_MIPS},
{"x86", "X86 architecture (including x86 & x86-64)", CS_ARCH_X86},
{"ppc", "PowerPC architecture", CS_ARCH_PPC},
{"sparc", "Sparc architecture", CS_ARCH_SPARC},
{"sysz", "SystemZ architecture", CS_ARCH_SYSZ},
{"xcore", "XCore architecture", CS_ARCH_XCORE},
{"m68k", "68K architecture", CS_ARCH_M68K},
{"tms320c64x", "TMS320C64x architecture", CS_ARCH_TMS320C64X},
{"m680x", "680X architecture", CS_ARCH_M680X},
{"evm", "Ethereum architecture", CS_ARCH_EVM},
{"mos65xx", "MOS65XX architecture (including MOS6502)", CS_ARCH_MOS65XX},
};

typedef struct mode_descr {
	char mode[16];
	char details[64];
	cs_mode mode_id;
} mode_descr;
static const mode_descr cs_modes[] = {
{"little_endian", "little-endian mode (default mode)", CS_MODE_LITTLE_ENDIAN},
{"arm", "32-bit ARM", CS_MODE_ARM},
{"16", "16-bit mode (X86)", CS_MODE_16},
{"32", "32-bit mode (X86)", CS_MODE_32},
{"64", "64-bit mode (X86, PPC)", CS_MODE_64},
{"thumb", "ARM's Thumb mode, including Thumb-2", CS_MODE_THUMB},
{"mclass", "ARM's Cortex-M series", CS_MODE_MCLASS},
{"v8", "ARMv8 A32 encodings for ARM", CS_MODE_V8},
{"micro", "MicroMips mode (MIPS)", CS_MODE_MICRO},
{"mips3", "Mips III ISA", CS_MODE_MIPS3},
{"mips32r6", "Mips32r6 ISA", CS_MODE_MIPS32R6},
{"mips2", "Mips II ISA", CS_MODE_MIPS2},
{"v9", "SparcV9 mode (Sparc)", CS_MODE_V9},
{"qpx", "Quad Processing eXtensions mode (PPC)", CS_MODE_QPX},
{"m68k_000", "M68K 68000 mode", CS_MODE_M68K_000},
{"m68k_010", "M68K 68010 mode", CS_MODE_M68K_010},
{"m68k_020", "M68K 68020 mode", CS_MODE_M68K_020},
{"m68k_030", "M68K 68030 mode", CS_MODE_M68K_030},
{"m68k_040", "M68K 68040 mode", CS_MODE_M68K_040},
{"m68k_060", "M68K 68060 mode", CS_MODE_M68K_060},
{"big_endian", "big-endian mode", CS_MODE_BIG_ENDIAN},
{"mips32", "Mips32 ISA (Mips)", CS_MODE_MIPS32},
{"mips64", "Mips64 ISA (Mips)", CS_MODE_MIPS64},
{"m680x_6301", "M680X Hitachi 6301,6303 mode", CS_MODE_M680X_6301},
{"m680x_6309", "M680X Hitachi 6309 mode", CS_MODE_M680X_6309},
{"m680x_6800", "M680X Motorola 6800,6802 mode", CS_MODE_M680X_6800},
{"m680x_6801", "M680X Motorola 6801,6803 mode", CS_MODE_M680X_6801},
{"m680x_6805", "M680X Motorola/Freescale 6805 mode", CS_MODE_M680X_6805},
{"m680x_6808", "M680X Motorola/Freescale/NXP 68HC08 mode", CS_MODE_M680X_6808},
{"m680x_6809", "M680X Motorola 6809 mode", CS_MODE_M680X_6809},
{"m680x_6811", "M680X Motorola/Freescale/NXP 68HC11 mode", CS_MODE_M680X_6811},
{"m680x_cpu12", "M680X Motorola/Freescale/NXP CPU12 used on M68HC12/HCS12", CS_MODE_M680X_CPU12},
{"m680x_hcs08", "M680X Freescale/NXP HCS08 mode", CS_MODE_M680X_HCS08},
};

typedef struct syntax_descr {
	char sntx[16];
	char details[64];
	cs_opt_value sntx_id;
} syntax_descr;
static const syntax_descr cs_sntxs[] = {
{"default", "Default asm syntax", CS_OPT_SYNTAX_DEFAULT},
{"intel", "X86 Intel asm syntax - default on X86", CS_OPT_SYNTAX_INTEL},
{"att", "X86 ATT asm syntax", CS_OPT_SYNTAX_ATT},
{"noregname", "Prints register name with only number", CS_OPT_SYNTAX_NOREGNAME},
{"masm", "X86 Intel Masm syntax", CS_OPT_SYNTAX_MASM},
};

#define ARCH_FMT "%-13s - %s\n"

void disasm_print_options(void)
{
#define DISASM_PRINT_OPTS_LOOP(str, id)                                        \
puts("\n" str);                                                                \
for (size_t i = 0; i < ARR_SIZE(cs_ ## id ## s); ++i)                          \
	printf(ARCH_FMT, cs_ ## id ## s [i]. id, cs_ ## id ## s [i].details);

	DISASM_PRINT_OPTS_LOOP("Disassembly architectures possible:", arch);
	DISASM_PRINT_OPTS_LOOP("Disassembly modes:", mode);
	DISASM_PRINT_OPTS_LOOP("Disassembly syntaxes:", sntx);

	puts("");
	disasm_print_arch();
#undef DISASM_PRINT_OPTS_LOOP
}

void disasm_print_arch(void)
{
	puts("Disassembly architectures compiled in:");
	for (size_t i = 0; i < ARR_SIZE(cs_archs); ++i)
	{
		if (cs_support(cs_archs[i].arch_id))
			printf(ARCH_FMT, cs_archs[i].arch, cs_archs[i].details);
	}
}

#define DISASM_GET_OPT(id, farg, err_str, ret)        \
for (size_t i = 0; i < ARR_SIZE(cs_ ## id ## s); ++i) \
{                                                     \
	if (strcmp(farg, cs_ ## id ## s[i]. id) == 0)     \
		return cs_ ## id ## s[i]. id ## _id;          \
}                                                     \
DISASM_ERR_QUIT(err_str, farg);                       \
return ret; // never reached

static cs_arch get_arch(const char * arch)
{
DISASM_GET_OPT(arch, arch, "'%s' not a valid architecture", CS_ARCH_MAX);
}

static cs_mode get_mode(const char * mode)
{
DISASM_GET_OPT(mode, mode, "'%s' not a valid mode", CS_MODE_LITTLE_ENDIAN);
}

static cs_opt_value get_syntax(const char * syntax)
{
DISASM_GET_OPT(sntx, syntax, "'%s' not a valid syntax", CS_OPT_SYNTAX_DEFAULT);
}
#undef DISASM_GET_OPT

void disasm_get_cs_version(int * major, int * minor)
{
	cs_version(major, minor);
}

void disasm_init(
	const char * arch,
	const char * mode,
	const char * syntax,
	size_t start_addr
)
{
	module.disasm_calls = 0;
	module.arch = (arch) ? get_arch(arch) : CS_ARCH_X86;
	module.mode = (mode) ? get_mode(mode) : CS_MODE_64;
	module.syntax = (syntax) ? get_syntax(syntax) : CS_OPT_SYNTAX_DEFAULT;

	if (!cs_support(module.arch))
		CAPSTONE_ERR_QUIT("architecture: not compiled with '%s'", arch);

	module.curr_addr = start_addr;

	cs_err err = cs_open(module.arch, module.mode, &module.handle);
	if (err != CS_ERR_OK)
		CAPSTONE_ERR_QUIT(STR_ERR(cs_strerror(err)));

	if (syntax)
	{
		err = cs_option(module.handle, CS_OPT_SYNTAX, module.syntax);
		if (err != CS_ERR_OK)
			CAPSTONE_ERR_QUIT("syntax: %s", cs_strerror(err));
	}

	module.inst = cs_malloc(module.handle);
	if (!module.inst)
		CAPSTONE_ERR_QUIT("couldn't allocate memory");
}

void disasm_disasm(FILE * where, const char * hex)
{
	++module.disasm_calls;

	size_t buff_len = 0;
	const char * h2b_err = NULL;
	size_t * ind_map = NULL;

	byte * buff = hex2bytes(hex, &buff_len, &ind_map, &h2b_err);
	if (!buff)
	{
		DISASM_ERR_PRINT(STR_ERR(h2b_err));
		err_out("string: '%s'\n", hex);
		err_exit();
	}

	const byte * cbuff = buff;
	size_t cbuff_len = buff_len;
	size_t start_addr = module.curr_addr;

	cs_insn * inst = module.inst;
	while (cs_disasm_iter(module.handle,
		&cbuff, &cbuff_len, &module.curr_addr, inst))
	{
		fprintf(where, "0x%04jx | ", inst->address);

		for (size_t j = 0; j < inst->size; ++j)
			fprintf(where, "%02x ", inst->bytes[j]);

		fprintf(where, "| %s %s\n", inst->mnemonic, inst->op_str);
	}

	cs_err err = cs_errno(module.handle);
	if (err != CS_ERR_OK)
		CAPSTONE_ERR_QUIT(STR_ERR(cs_strerror(err)));

	if (module.curr_addr < (start_addr + buff_len))
	{
		DISASM_ERR_PRINT("invalid instruction at address 0x%04jx in string %zu",
			module.curr_addr, module.disasm_calls);

		err_out("%s\n", hex);

		char ch = 0;
		size_t bad_pos = ind_map[module.curr_addr - start_addr];
		for (size_t i = 0; i < bad_pos; ++i)
		{
			ch = hex[i];
			if (!isspace(ch))
				ch = ' ';

			err_out("%c", ch);
		}
		err_out("%c\n", '^');
		err_exit();
	}

	free(ind_map);
	free(buff);
}

void disasm_close(void)
{
	cs_free(module.inst, 1);
	cs_close(&module.handle);
}
