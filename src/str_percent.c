/* str_percent.c -- create a C backslashed escaped string

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

#include "str_percent.h"

char *str_percent (char *dst, size_t dstlen,
		   const unsigned char *src, size_t srclen,
		   const char *alsosafe)
{
  static char hexit[] = { '0', '1', '2', '3', '4', '5', '6', '7',
			  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
  int i;  /* index down the dst */
  int n;  /* index down the src */
  for (i=0,n=0; n<srclen; n++) {

    /* Worst case, need 4 dst bytes for the next src byte. 
       percent hexit hexit null */
    if ((dstlen - i) < 4) { dst[i] = '\0'; return dst; }

    if (((src[n] >= 'A') && (src[n] <= 'Z'))
	|| ((src[n] >= 'a') && (src[n] <= 'z'))
	|| ((src[n] >= '0') && (src[n] <= '9'))) {
      dst[i++] = src[n];
    } else if ((src[n]) && (strchr(alsosafe, src[n]) != NULL)) {
      dst[i++] = src[n];
    } else {
      dst[i++] = '%';
      dst[i++] = hexit[(src[n] >> 4) & 0x0f];
      dst[i++] = hexit[src[n] & 0x0f];
    }
    dst[i] = '\0';
  }
  return dst;
}

#ifdef STRPERCENT_DEMO

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main (int argc, char *argv[])
{
  switch (getopt(argc, argv, "ai")) {
  case 'a':
    {
      char demo_src[256];
      char demo_dst[3*sizeof(demo_src) + 1];
      int i;
      for (i=0; i<256; i++)
	demo_src[i] = (char) i;
      (void) str_percent(demo_dst, sizeof(demo_dst),
			 demo_src, sizeof(demo_src),
			 "");
      printf("\"%.*s\"\n", sizeof(demo_dst), demo_dst);
    }
    break;
  case 'i':
    {
      char demo_src[256];
      char demo_dst[3*sizeof(demo_src) + 1];
      size_t rv = 1;
      while (rv && !(feof(stdin) || ferror(stdin))) {
	rv = fread(demo_src, 1, sizeof(demo_src), stdin);
	printf("\"%s\"\n", str_percent(demo_dst, sizeof(demo_dst),
				       demo_src, rv, ""));
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
