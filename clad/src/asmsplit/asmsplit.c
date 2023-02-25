#include "asmsplit.h"

#include <ctype.h>

const char * asm_instr_next(
	const char * asm_str,
	char * buff,
	size_t len,
	const char ** out_err
)
{
	static const char err_len[] = "asm_instr_next(): instruction string buffer too small";
	
	const char * start = asm_str;
	char ch = *start;
	const char * end = NULL;
	size_t n = 0;
	size_t buff_end = 0;
	
	if (!len)
		goto small_buff;

	
	while (ch && (isspace(ch) || ';' == ch))
		ch = *(++start);
	
	if ('\0' == *start)
		return NULL;
	
	end = start;
	buff_end = len-1;
		
	ch = *end;
	while (ch != '\0' && ch != '\n' && ch != ';')
	{
		if (n >= buff_end)
			goto small_buff;
		
		buff[n++] = ch;
		ch = *(++end);
	}
	buff[n] = '\0';
	
	while (n && isspace(buff[n-1]))
		--n;
		
	buff[n] = '\0';
	return end;
	
small_buff:
	if (out_err)
		*out_err = err_len;
	return NULL;
}
