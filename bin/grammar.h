/* A Bison parser, made by GNU Bison 2.7.12-4996.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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

#ifndef YY_YY_GRAMMAR_H_INCLUDED
# define YY_YY_GRAMMAR_H_INCLUDED
/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     ANY = 258,
     IP = 259,
     IF = 260,
     MAC = 261,
     MPLS = 262,
     TOS = 263,
     DIR = 264,
     FLAGS = 265,
     PROTO = 266,
     MASK = 267,
     HOSTNAME = 268,
     NET = 269,
     PORT = 270,
     FWDSTAT = 271,
     IN = 272,
     OUT = 273,
     SRC = 274,
     DST = 275,
     EQ = 276,
     LT = 277,
     GT = 278,
     PREV = 279,
     NEXT = 280,
     NUMBER = 281,
     STRING = 282,
     IDENT = 283,
     PORTNUM = 284,
     ICMP_TYPE = 285,
     ICMP_CODE = 286,
     ENGINE_TYPE = 287,
     ENGINE_ID = 288,
     AS = 289,
     PACKETS = 290,
     BYTES = 291,
     FLOWS = 292,
     PPS = 293,
     BPS = 294,
     BPP = 295,
     DURATION = 296,
     NOT = 297,
     IPV4 = 298,
     IPV6 = 299,
     BGPNEXTHOP = 300,
     ROUTER = 301,
     VLAN = 302,
     CLIENT = 303,
     SERVER = 304,
     APP = 305,
     LATENCY = 306,
     SYSID = 307,
     ASA = 308,
     REASON = 309,
     DENIED = 310,
     XEVENT = 311,
     XIP = 312,
     XNET = 313,
     XPORT = 314,
     INGRESS = 315,
     EGRESS = 316,
     ACL = 317,
     ACE = 318,
     XACE = 319,
     NAT = 320,
     ADD = 321,
     EVENT = 322,
     VRF = 323,
     NPORT = 324,
     NIP = 325,
     PBLOCK = 326,
     START = 327,
     END = 328,
     STEP = 329,
     SIZE = 330,
     OR = 331,
     AND = 332,
     NEGATE = 333
   };
#endif
/* Tokens.  */
#define ANY 258
#define IP 259
#define IF 260
#define MAC 261
#define MPLS 262
#define TOS 263
#define DIR 264
#define FLAGS 265
#define PROTO 266
#define MASK 267
#define HOSTNAME 268
#define NET 269
#define PORT 270
#define FWDSTAT 271
#define IN 272
#define OUT 273
#define SRC 274
#define DST 275
#define EQ 276
#define LT 277
#define GT 278
#define PREV 279
#define NEXT 280
#define NUMBER 281
#define STRING 282
#define IDENT 283
#define PORTNUM 284
#define ICMP_TYPE 285
#define ICMP_CODE 286
#define ENGINE_TYPE 287
#define ENGINE_ID 288
#define AS 289
#define PACKETS 290
#define BYTES 291
#define FLOWS 292
#define PPS 293
#define BPS 294
#define BPP 295
#define DURATION 296
#define NOT 297
#define IPV4 298
#define IPV6 299
#define BGPNEXTHOP 300
#define ROUTER 301
#define VLAN 302
#define CLIENT 303
#define SERVER 304
#define APP 305
#define LATENCY 306
#define SYSID 307
#define ASA 308
#define REASON 309
#define DENIED 310
#define XEVENT 311
#define XIP 312
#define XNET 313
#define XPORT 314
#define INGRESS 315
#define EGRESS 316
#define ACL 317
#define ACE 318
#define XACE 319
#define NAT 320
#define ADD 321
#define EVENT 322
#define VRF 323
#define NPORT 324
#define NIP 325
#define PBLOCK 326
#define START 327
#define END 328
#define STEP 329
#define SIZE 330
#define OR 331
#define AND 332
#define NEGATE 333



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{
/* Line 2053 of yacc.c  */
#line 99 "grammar.y"

	uint64_t		value;
	char			*s;
	FilterParam_t	param;
	void			*list;


/* Line 2053 of yacc.c  */
#line 221 "grammar.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */

#endif /* !YY_YY_GRAMMAR_H_INCLUDED  */
