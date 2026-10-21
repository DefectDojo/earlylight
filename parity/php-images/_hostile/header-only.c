/* A C program with PHP's X-Powered-By header as a NUL-terminated string, but no
 * Zend Engine banner: it is not PHP. */
#include <stdio.h>
const char *hdr = "X-Powered-By: PHP/8.3.20";
int main(int argc, char **argv) { puts(hdr); return 0; }
