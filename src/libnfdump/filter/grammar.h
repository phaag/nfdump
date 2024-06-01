/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     EQ = 258,
     LT = 259,
     GT = 260,
     LE = 261,
     GE = 262,
     ANY = 263,
     NOT = 264,
     IDENT = 265,
     COUNT = 266,
     IP = 267,
     IPV4 = 268,
     IPV6 = 269,
     NET = 270,
     SRC = 271,
     DST = 272,
     IN = 273,
     OUT = 274,
     PREV = 275,
     NEXT = 276,
     BGP = 277,
     ROUTER = 278,
     INGRESS = 279,
     EGRESS = 280,
     NAT = 281,
     XLATE = 282,
     TUN = 283,
     ENGINE = 284,
     ENGINETYPE = 285,
     ENGINEID = 286,
     EXPORTER = 287,
     DURATION = 288,
     PPS = 289,
     BPS = 290,
     BPP = 291,
     FLAGS = 292,
     PROTO = 293,
     PORT = 294,
     AS = 295,
     IF = 296,
     VLAN = 297,
     MPLS = 298,
     MAC = 299,
     ICMP = 300,
     ICMPTYPE = 301,
     ICMPCODE = 302,
     PACKETS = 303,
     BYTES = 304,
     FLOWS = 305,
     ETHERTYPE = 306,
     MASK = 307,
     FLOWDIR = 308,
     TOS = 309,
     FWDSTAT = 310,
     LATENCY = 311,
     ASA = 312,
     ACL = 313,
     PAYLOAD = 314,
     GEO = 315,
     VRF = 316,
     OBSERVATION = 317,
     PF = 318,
     STRING = 319,
     NUMBER = 320,
     OR = 321,
     AND = 322,
     NEGATE = 323
   };
#endif
/* Tokens.  */
#define EQ 258
#define LT 259
#define GT 260
#define LE 261
#define GE 262
#define ANY 263
#define NOT 264
#define IDENT 265
#define COUNT 266
#define IP 267
#define IPV4 268
#define IPV6 269
#define NET 270
#define SRC 271
#define DST 272
#define IN 273
#define OUT 274
#define PREV 275
#define NEXT 276
#define BGP 277
#define ROUTER 278
#define INGRESS 279
#define EGRESS 280
#define NAT 281
#define XLATE 282
#define TUN 283
#define ENGINE 284
#define ENGINETYPE 285
#define ENGINEID 286
#define EXPORTER 287
#define DURATION 288
#define PPS 289
#define BPS 290
#define BPP 291
#define FLAGS 292
#define PROTO 293
#define PORT 294
#define AS 295
#define IF 296
#define VLAN 297
#define MPLS 298
#define MAC 299
#define ICMP 300
#define ICMPTYPE 301
#define ICMPCODE 302
#define PACKETS 303
#define BYTES 304
#define FLOWS 305
#define ETHERTYPE 306
#define MASK 307
#define FLOWDIR 308
#define TOS 309
#define FWDSTAT 310
#define LATENCY 311
#define ASA 312
#define ACL 313
#define PAYLOAD 314
#define GEO 315
#define VRF 316
#define OBSERVATION 317
#define PF 318
#define STRING 319
#define NUMBER 320
#define OR 321
#define AND 322
#define NEGATE 323




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 166 "filter/grammar.y"
{
	uint64_t			value;
	char					*s;
	FilterParam_t	param;
	void					*list;
}
/* Line 1529 of yacc.c.  */
#line 192 "filter/grammar.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

