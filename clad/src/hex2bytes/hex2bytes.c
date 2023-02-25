#include "hex2bytes.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>

#define IGNORE '!'

static const char * next_hex(const char * str)
{
	const char * pos = str;
	bool ignore = false;

	for (char ch = 0; *pos; ++pos)
	{
		ch = *pos;

		if (!ignore)
		{
			if(IGNORE == ch)
				ignore = true;
		}
		else if (ignore)
		{
			if (!isspace(ch))
				continue;
			else
				ignore = false;
		}

		if ('0' == ch)
		{
			char ch2 = *(pos+1);
			if ('x' == ch2 || 'X' == ch2)
			{
				++pos;
				continue;
			}
		}

		if (isxdigit(ch))
			return pos;
	}

	return NULL;
}

static size_t num_bytes(const char * hex)
{
	size_t bytes = 0;
	const char * next = hex-1;

	while ((next = next_hex(next+1)))
		++bytes;

	return ((bytes / 2) + (bytes % 2));
}

static byte hex_val(char hxd)
{
	switch (hxd)
	{
		case '0': return 0x00;
		case '1': return 0x01;
		case '2': return 0x02;
		case '3': return 0x03;
		case '4': return 0x04;
		case '5': return 0x05;
		case '6': return 0x06;
		case '7': return 0x07;
		case '8': return 0x08;
		case '9': return 0x09;
		case 'a': return 0x0a;
		case 'b': return 0x0b;
		case 'c': return 0x0c;
		case 'd': return 0x0d;
		case 'e': return 0x0e;
		case 'f': return 0x0f;
		case 'A': return 0x0A;
		case 'B': return 0x0B;
		case 'C': return 0x0C;
		case 'D': return 0x0D;
		case 'E': return 0x0E;
		case 'F': return 0x0F;
		default: break;
	}
	return 0x10;
}

byte * hex2bytes(
	const char * hex,
	size_t * out_len,
	size_t ** out_index_map,
	const char ** out_err
)
{
	static const char err_mem[] = "hex2bytes(): calloc() failed";
	static const char err_bug[] = "hex2bytes(): bug in calculating hex value";
	static const char err_nohex[] = "hex2bytes(): no hex values in string";

	const char * curr_err = NULL;
	size_t len = num_bytes(hex);

	byte hval = 0;
	size_t pos = 0;
	unsigned int which = 0;
	const char * next = hex-1;
	byte * buff = NULL;
	size_t * ind_map = NULL;
	size_t num_byte = 0;
	
	if (0 == len)
	{
		curr_err = err_nohex;
		goto bad;
	}

	buff = (byte *)calloc(1, len);
	if (!buff)
	{
		curr_err = err_mem;
		goto bad;
	}
	
	if (out_index_map)
	{
		ind_map = (size_t *)calloc(1, len * sizeof(*ind_map));
		if (!ind_map)
		{
			free(buff);
			curr_err = err_mem;
			goto bad;
		}
	}
	
	while ((next = next_hex(next+1)))
	{
		if ((hval = hex_val(*next)) > 0x0F)
		{
			free(buff);
			
			if (out_index_map)
				free(ind_map);
				
			curr_err = err_bug;
			goto bad;
		}

		if (0 == which)
		{
			if (out_index_map)
				ind_map[num_byte++] = next - hex;
				
			buff[pos] = (hval << 4);
		}
		else
		{
			buff[pos] |= hval;
			++pos;
		}

		which ^= 1;
	}

	*out_len = len;
	
	if (out_index_map)
		*out_index_map = ind_map;
		
	return buff;

bad:
	if (out_err)
		*out_err = curr_err;

	return NULL;
}
