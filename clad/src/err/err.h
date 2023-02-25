#ifndef CLAD_ERR_H
#define CLAD_ERR_H
void err_set_prog_name(const char * name);
void err_out(const char * str, ...);
void err_print(const char * msg, ...);
void err_quit(const char * msg, ...);
void err_exit(void);
#endif
