/* str_quotify.c -- create a C backslashed escaped string

   Copyright (C) 2007 by Mark Atwood <me@mark.atwood.name>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#include <string.h>
#include <ctype.h>
#include "str_quotify.h"

char *str_quotify (char *dst, size_t dstlen,
		   const char *src, size_t srclen)
{
  static char hexit[] = { '0', '1', '2', '3', '4', '5', '6', '7',
			  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
  int i;  /* index down the dst */
  int n;  /* index down the src */
  for (i=0,n=0; n<srclen; n++) {

    /* Worst case, need 5 dst bytes for the next src byte. 
       backslash x hexit hexit null */
    if ((dstlen - i) < 5) { dst[i] = '\0'; return dst; }

    if (src[n] == 0x00) {  /* null */
      dst[i++] = '\\'; dst[i++] = '0';
    } else if (src[n] == 0x07) {  /* bell */
      dst[i++] = '\\'; dst[i++] = 'a';
    } else if (src[n] == 0x08) {  /* backspace */
      dst[i++] = '\\'; dst[i++] = 'b';
    } else if (src[n] == 0x09) {  /* horiz tab */
      dst[i++] = '\\'; dst[i++] = 't';
    } else if (src[n] == 0x0a) {  /* line feed */
      dst[i++] = '\\'; dst[i++] = 'n';
    } else if (src[n] == 0x0b) {  /* vert tab */
      dst[i++] = '\\'; dst[i++] = 'v';
    } else if (src[n] == 0x0c) {  /* formfeed */
      dst[i++] = '\\'; dst[i++] = 'f';
    } else if (src[n] == 0x0d) {  /* carrage return */
      dst[i++] = '\\'; dst[i++] = 'r';
    } else if (src[n] == 0x22) {  /* quotation mark */
      dst[i++] = '\\'; dst[i++] = 0x22;
    } else if (src[n] == 0x5C) {  /* backslash */
      dst[i++] = '\\'; dst[i++] = 0x5C;
    } else if (src[n] == ' ') {
      dst[i++] = ' ';
    } else if (isgraph(src[n])) {
      dst[i++] = src[n];
    } else {
      dst[i++] = '\\';
      dst[i++] = 'x';
      dst[i++] = hexit[(src[n] >> 4) & 0x0f];
      dst[i++] = hexit[src[n] & 0x0f];
    }
    dst[i] = '\0';
  }
  return dst;
}

#ifdef STRQUOTIFY_DEMO

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main (int argc, char *argv[])
{
  switch (getopt(argc, argv, "ai")) {
  case 'a':
    {
      char demo_src[256];
      char demo_dst[4*sizeof(demo_src) + 1];
      int i;
      for (i=0; i<256; i++)
	demo_src[i] = (char) i;
      (void) str_quotify(demo_dst, sizeof(demo_dst),
			 demo_src, sizeof(demo_src));
      printf("\"%.*s\"\n", sizeof(demo_dst), demo_dst);
    }
    break;
  case 'i':
    {
      char demo_src[256];
      char demo_dst[4*sizeof(demo_src) + 1];
      size_t rv = 1;
      while (rv && !(feof(stdin) || ferror(stdin))) {
	rv = fread(demo_src, 1, sizeof(demo_src), stdin);
	printf("\"%s\"\n", str_quotify(demo_dst, sizeof(demo_dst),
				       demo_src, rv));
      }
    }
    break;
  case -1:
  case '?':
  default:
    fprintf(stderr,
	    "usage: %s [-a] [-i]\n"
	    "  -a   output a quotified string of all 256 chars in order\n"
	    "  -i   read from stdin, output quotified strings\n",
	    argv[0]);
  }

}

#endif
