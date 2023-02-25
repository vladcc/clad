#ifndef CLAD_ASM_SPLIT_H

#include <stddef.h>

const char * asm_instr_next(
	const char * asm_str,
	char * buff,
	size_t len,
	const char ** out_err
);

#endif
