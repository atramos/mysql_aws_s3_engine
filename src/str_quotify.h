/* str_quotify.h -- create a C backslashed escaped string

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

#ifndef _INCLUDE_STRQUOTIFY
#define _INCLUDE_STRQUOTIFY

#ifdef __cplusplus
extern "C" {
#endif

/* Copy src into dst, converting it a C style backslashed escaped
   string.  All control characters, high bit characters, the ASCII
   NULL, and all whitespace except the space character itself will be
   converted. The backslash and the quotation characters will be
   escaped as well. If the dst buffer isn't long enough, as much as
   will fit will be done.  The dst buffer will be null terminated,
   so it can safely be treated as a C string.  The dst buffer will
   also be returned.
*/   

char *str_quotify (char *dst, size_t dstlen,
		   const char *src, size_t srclen);

#ifdef __cplusplus
}
#endif

#endif /* ndef _INCLUDE_STRQUOTIFY */
