#ifndef CLAD_ASM_H
#define CLAD_ASM_H

#define ASM_MAX_INSTR_DEFAULT 1024

void asm_print_options(void);
void asm_print_arch(void);
void asm_get_ks_version(unsigned int * major, unsigned int * minor);

void asm_init(
	const char * arch,
	const char * mode,
	const char * syntax,
	size_t start_addr,
	size_t max_single_instr_len
);

void asm_asm(FILE * where, const char * asm_str);
void asm_close(void);

#endif
