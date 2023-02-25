#ifndef HEX2BYTES_H
#define HEX2BYTES_H

#include <stddef.h>

typedef unsigned char byte;

byte * hex2bytes(
	const char * hex,
	size_t * out_len,
	size_t ** out_index_map,
	const char ** out_err
);

#endif
