#ifndef CLAD_ASM_H
#define CLAD_ASM_H

void asm_print_options(void);
void asm_print_arch(void);
void asm_get_ks_version(unsigned int * major, unsigned int * minor);

void asm_init(
	const char * arch,
	const char * mode,
	const char * syntax,
	size_t start_addr
);

void asm_asm(
	FILE * where,
	const char * asm_str,
	char * one_instr_buff,
	size_t oib_size
);

void asm_close(void);

#endif
