/* Adversarial forgery: both strings PHP compiles in, NUL-terminated, in a program
 * that is not PHP. By the README's detection rule this counts as PHP. */
#include <stdio.h>
const char *hdr = "X-Powered-By: PHP/8.3.20";
const char *zend = "Zend Engine v4.3.20, Copyright (c) Zend Technologies";
int main(void) { puts(hdr); puts(zend); return 0; }
