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
{"arm64", "ARM64", CS_ARCH_ARM64},
{"sysz", "SystemZ architecture", CS_ARCH_SYSZ},
{"mips", "Mips architecture", CS_ARCH_MIPS},
{"x86", "X86 architecture (including x86 & x86-64)", CS_ARCH_X86},
{"ppc", "PowerPC architecture", CS_ARCH_PPC},
{"sparc", "Sparc architecture", CS_ARCH_SPARC},
{"xcore", "XCore architecture", CS_ARCH_XCORE},
{"m68k", "68K architecture", CS_ARCH_M68K},
{"tms320c64x", "TMS320C64x architecture", CS_ARCH_TMS320C64X},
{"m680x", "680X architecture", CS_ARCH_M680X},
{"evm", "Ethereum architecture", CS_ARCH_EVM},
{"mos65xx", "MOS65XX architecture (including MOS6502)", CS_ARCH_MOS65XX},
{"wasm", "WebAssembly architecture", CS_ARCH_WASM},
{"bpf", "Berkeley Packet Filter architecture (including eBPF)", CS_ARCH_BPF},
{"riscv", "RISCV architecture", CS_ARCH_RISCV},
{"sh", "SH architecture", CS_ARCH_SH},
{"tricore", "TriCore architecture", CS_ARCH_TRICORE},
{"alpha", "Alpha architecture", CS_ARCH_ALPHA},
{"hppa", "HPPA architecture", CS_ARCH_HPPA},
{"loongarch", "LoongArch architecture", CS_ARCH_LOONGARCH},
{"xtensa", "Xtensa architecture", CS_ARCH_XTENSA},
{"arc", "ARC architecture", CS_ARCH_ARC},
};

typedef struct mode_descr {
	char mode[24];
	char details[80];
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
{"apple_proprietary", "Enable Apple proprietary AArch64 instructions like AMX, MUL53, and others.", CS_MODE_APPLE_PROPRIETARY},
{"v9", "SparcV9 mode (Sparc)", CS_MODE_V9},
{"qpx", "Quad Processing eXtensions mode (PPC)", CS_MODE_QPX},
{"spe", "Signal Processing Engine mode (PPC)", CS_MODE_SPE},
{"booke", "Book-E mode (PPC)", CS_MODE_BOOKE},
{"ps", "Paired-singles mode (PPC)", CS_MODE_PS},
{"aix_os", "PowerPC AIX-OS", CS_MODE_AIX_OS},
{"pwr7", "Power 7", CS_MODE_PWR7},
{"pwr8", "Power 8", CS_MODE_PWR8},
{"pwr9", "Power 9", CS_MODE_PWR9},
{"pwr10", "Power 10", CS_MODE_PWR10},
{"ppc_isa_future", "Power ISA Future", CS_MODE_PPC_ISA_FUTURE},
{"modern_aix_as", "PowerPC AIX-OS with modern assembly", CS_MODE_MODERN_AIX_AS},
{"msync", "PowerPC Has only the msync instruction instead of sync. Implies BOOKE", CS_MODE_MSYNC},
{"m68k_000", "M68K 68000 mode", CS_MODE_M68K_000},
{"m68k_010", "M68K 68010 mode", CS_MODE_M68K_010},
{"m68k_020", "M68K 68020 mode", CS_MODE_M68K_020},
{"m68k_030", "M68K 68030 mode", CS_MODE_M68K_030},
{"m68k_040", "M68K 68040 mode", CS_MODE_M68K_040},
{"m68k_060", "M68K 68060 mode", CS_MODE_M68K_060},
{"big_endian", "big-endian mode", CS_MODE_BIG_ENDIAN},
{"mips16", "Generic mips16", CS_MODE_MIPS16},
{"mips32", "Generic mips32", CS_MODE_MIPS32},
{"mips64", "Generic mips64", CS_MODE_MIPS64},
{"micro", "microMips", CS_MODE_MICRO},
{"mips1", "Mips I ISA Support", CS_MODE_MIPS1},
{"mips2", "Mips II ISA Support", CS_MODE_MIPS2},
{"mips32r2", "Mips32r2 ISA Support", CS_MODE_MIPS32R2},
{"mips32r3", "Mips32r3 ISA Support", CS_MODE_MIPS32R3},
{"mips32r5", "Mips32r5 ISA Support", CS_MODE_MIPS32R5},
{"mips32r6", "Mips32r6 ISA Support", CS_MODE_MIPS32R6},
{"mips3", "MIPS III ISA Support", CS_MODE_MIPS3},
{"mips4", "MIPS IV ISA Support", CS_MODE_MIPS4},
{"mips5", "MIPS V ISA Support", CS_MODE_MIPS5},
{"mips64r2", "Mips64r2 ISA Support", CS_MODE_MIPS64R2},
{"mips64r3", "Mips64r3 ISA Support", CS_MODE_MIPS64R3},
{"mips64r5", "Mips64r5 ISA Support", CS_MODE_MIPS64R5},
{"mips64r6", "Mips64r6 ISA Support", CS_MODE_MIPS64R6},
{"octeon", "Octeon cnMIPS Support", CS_MODE_OCTEON},
{"octeonp", "Octeon+ cnMIPS Support", CS_MODE_OCTEONP},
{"nanomips", "Generic nanomips", CS_MODE_NANOMIPS},
{"nms1", "nanoMips NMS1", CS_MODE_NMS1},
{"i7200", "nanoMips I7200", CS_MODE_I7200},
{"mips_nofloat", "Disable floating points ops", CS_MODE_MIPS_NOFLOAT},
{"mips_ptr64", "Mips pointers are 64-bit", CS_MODE_MIPS_PTR64},
{"micro32r3", "microMips32r3", CS_MODE_MICRO32R3},
{"micro32r6", "microMips32r6", CS_MODE_MICRO32R6},
{"m680x_6301", "M680X Hitachi 6301,6303 mode", CS_MODE_M680X_6301},
{"m680x_6309", "M680X Hitachi 6309 mode", CS_MODE_M680X_6309},
{"m680x_6800", "M680X Motorola 6800,6802 mode", CS_MODE_M680X_6800},
{"m680x_6801", "M680X Motorola 6801,6803 mode", CS_MODE_M680X_6801},
{"m680x_6805", "M680X Motorola/Freescale 6805 mode", CS_MODE_M680X_6805},
{"m680x_6808", "M680X Motorola/Freescale/NXP 68HC08 mode", CS_MODE_M680X_6808},
{"m680x_6809", "M680X Motorola 6809 mode", CS_MODE_M680X_6809},
{"m680x_6811", "M680X Motorola/Freescale/NXP 68HC11 mode", CS_MODE_M680X_6811},
{"m680x_cpu12", "M680X Motorola/Freescale/NXP CPU12", CS_MODE_M680X_CPU12},
{"m680x_hcs08", "M680X Freescale/NXP HCS08 mode", CS_MODE_M680X_HCS08},
{"bpf_classic", "Classic BPF mode (default)", CS_MODE_BPF_CLASSIC},
{"bpf_extended", "Extended BPF mode", CS_MODE_BPF_EXTENDED},
{"riscv32", "RISCV RV32G", CS_MODE_RISCV32},
{"riscv64", "RISCV RV64G", CS_MODE_RISCV64},
{"riscvc", "RISCV compressed instructure mode", CS_MODE_RISCVC},
{"mos65xx_6502", "MOS65XXX MOS 6502", CS_MODE_MOS65XX_6502},
{"mos65xx_65c02", "MOS65XXX WDC 65c02", CS_MODE_MOS65XX_65C02},
{"mos65xx_w65c02", "MOS65XXX WDC W65c02", CS_MODE_MOS65XX_W65C02},
{"mos65xx_65816", "MOS65XXX WDC 65816, 8-bit m/x", CS_MODE_MOS65XX_65816},
{"mos65xx_65816_long_m", "MOS65XXX WDC 65816, 16-bit m, 8-bit x", CS_MODE_MOS65XX_65816_LONG_M},
{"mos65xx_65816_long_x", "MOS65XXX WDC 65816, 8-bit m, 16-bit x", CS_MODE_MOS65XX_65816_LONG_X},
{"mos65xx_65816_long_mx", "MOS65XXX WDC 65816, long_m|long_x", CS_MODE_MOS65XX_65816_LONG_MX},
{"sh2", "SH2", CS_MODE_SH2},
{"sh2a", "SH2A", CS_MODE_SH2A},
{"sh3", "SH3", CS_MODE_SH3},
{"sh4", "SH4", CS_MODE_SH4},
{"sh4a", "SH4A", CS_MODE_SH4A},
{"shfpu", "w/ FPU", CS_MODE_SHFPU},
{"shdsp", "w/ DSP", CS_MODE_SHDSP},
{"tricore_110", "Tricore 1.1", CS_MODE_TRICORE_110},
{"tricore_120", "Tricore 1.2", CS_MODE_TRICORE_120},
{"tricore_130", "Tricore 1.3", CS_MODE_TRICORE_130},
{"tricore_131", "Tricore 1.3.1", CS_MODE_TRICORE_131},
{"tricore_160", "Tricore 1.6", CS_MODE_TRICORE_160},
{"tricore_161", "Tricore 1.6.1", CS_MODE_TRICORE_161},
{"tricore_162", "Tricore 1.6.2", CS_MODE_TRICORE_162},
{"tricore_180", "Tricore 1.8.0", CS_MODE_TRICORE_180},
{"hppa_11", "HPPA 1.1", CS_MODE_HPPA_11},
{"hppa_20", "HPPA 2.0", CS_MODE_HPPA_20},
{"hppa_20w", "HPPA 2.0 wide", CS_MODE_HPPA_20W},
{"loongarch32", "LoongArch32", CS_MODE_LOONGARCH32},
{"loongarch64", "LoongArch64", CS_MODE_LOONGARCH64},
{"systemz_arch8", "Enables features of the ARCH8 processor", CS_MODE_SYSTEMZ_ARCH8},
{"systemz_arch9", "Enables features of the ARCH9 processor", CS_MODE_SYSTEMZ_ARCH9},
{"systemz_arch10", "Enables features of the ARCH10 processor", CS_MODE_SYSTEMZ_ARCH10},
{"systemz_arch11", "Enables features of the ARCH11 processor", CS_MODE_SYSTEMZ_ARCH11},
{"systemz_arch12", "Enables features of the ARCH12 processor", CS_MODE_SYSTEMZ_ARCH12},
{"systemz_arch13", "Enables features of the ARCH13 processor", CS_MODE_SYSTEMZ_ARCH13},
{"systemz_arch14", "Enables features of the ARCH14 processor", CS_MODE_SYSTEMZ_ARCH14},
{"systemz_z10", "Enables features of the Z10 processor", CS_MODE_SYSTEMZ_Z10},
{"systemz_z196", "Enables features of the Z196 processor", CS_MODE_SYSTEMZ_Z196},
{"systemz_zec12", "Enables features of the ZEC12 processor", CS_MODE_SYSTEMZ_ZEC12},
{"systemz_z13", "Enables features of the Z13 processor", CS_MODE_SYSTEMZ_Z13},
{"systemz_z14", "Enables features of the Z14 processor", CS_MODE_SYSTEMZ_Z14},
{"systemz_z15", "Enables features of the Z15 processor", CS_MODE_SYSTEMZ_Z15},
{"systemz_z16", "Enables features of the Z16 processor", CS_MODE_SYSTEMZ_Z16},
{"systemz_generic", "Enables features of the generic processor", CS_MODE_SYSTEMZ_GENERIC},
{"xtensa_esp32", "Xtensa ESP32", CS_MODE_XTENSA_ESP32},
{"xtensa_esp32s2", "Xtensa ESP32S2", CS_MODE_XTENSA_ESP32S2},
{"xtensa_esp8266", "Xtensa ESP328266", CS_MODE_XTENSA_ESP8266},
};

typedef struct syntax_descr {
	char sntx[16];
	char details[80];
	cs_opt_value sntx_id;
} syntax_descr;
static const syntax_descr cs_sntxs[] = {
{"default", "Default asm syntax.", CS_OPT_SYNTAX_DEFAULT},
{"intel", "X86 Intel asm syntax - default on X86.", CS_OPT_SYNTAX_INTEL},
{"att", "X86 ATT asm syntax.", CS_OPT_SYNTAX_ATT},
{"noregname", "Prints register name with only number", CS_OPT_SYNTAX_NOREGNAME},
{"masm", "X86 Intel Masm syntax.", CS_OPT_SYNTAX_MASM},
{"motorola", "MOS65XX use $ as hex prefix", CS_OPT_SYNTAX_MOTOROLA},
{"cs_reg_alias", "Prints common register alias which are not defined in LLVM (ARM: r9 = sb etc.)", CS_OPT_SYNTAX_CS_REG_ALIAS},
{"percent", "Prints the % in front of PPC registers.", CS_OPT_SYNTAX_PERCENT},
{"no_dollar", "Does not print the $ in front of Mips, LoongArch registers.", CS_OPT_SYNTAX_NO_DOLLAR},
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
