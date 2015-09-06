/* A Bison parser, made by GNU Bison 2.7.12-4996.  */

/* Bison implementation for Yacc-like parsers in C
   
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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.7.12-4996"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* Copy the first part of user declarations.  */
/* Line 371 of yacc.c  */
#line 41 "grammar.y"


#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nf_common.h"
#include "rbtree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nftree.h"
#include "ipconv.h"
#include "util.h"

/*
 * function prototypes
 */
static void  yyerror(char *msg);

static uint32_t ChainHosts(uint64_t *offsets, uint64_t *hostlist, int num_records, int type);

static uint64_t VerifyMac(char *s);

enum { DIR_UNSPEC = 1, 
	   SOURCE, DESTINATION, SOURCE_AND_DESTINATION, SOURCE_OR_DESTINATION, 
	   DIR_IN, DIR_OUT, 
	   IN_SRC, IN_DST, OUT_SRC, OUT_DST, 
	   ADJ_PREV, ADJ_NEXT };

enum { IS_START = 0, IS_END };

/* var defs */
extern int 			lineno;
extern char 		*yytext;
extern uint64_t		*IPstack;
extern uint32_t	StartNode;
extern uint16_t	Extended;
extern int (*FilterEngine)(uint32_t *);
extern char	*FilterFilename;

static uint32_t num_ip;

char yyerror_buff[256];

#define MPLSMAX 0x00ffffff

/* Line 371 of yacc.c  */
#line 126 "grammar.c"

# ifndef YY_NULL
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULL nullptr
#  else
#   define YY_NULL 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
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
/* Line 387 of yacc.c  */
#line 99 "grammar.y"

	uint64_t		value;
	char			*s;
	FilterParam_t	param;
	void			*list;


/* Line 387 of yacc.c  */
#line 333 "grammar.c"
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

/* Copy the second part of user declarations.  */

/* Line 390 of yacc.c  */
#line 361 "grammar.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef __attribute__
/* This feature is available in gcc versions 2.5 and later.  */
# if (! defined __GNUC__ || __GNUC__ < 2 \
      || (__GNUC__ == 2 && __GNUC_MINOR__ < 5))
#  define __attribute__(Spec) /* empty */
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif


/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(N) (N)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (YYID (0))
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  94
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   290

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  87
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  10
/* YYNRULES -- Number of rules.  */
#define YYNRULES  106
/* YYNRULES -- Number of states.  */
#define YYNSTATES  226

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   333

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      85,    86,    78,    76,    84,     2,     2,    83,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    81,     2,    82,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    77,    79,    80
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     6,     8,    11,    13,    15,    18,
      21,    26,    31,    35,    39,    43,    47,    51,    56,    60,
      63,    67,    74,    78,    85,    89,    93,    98,   103,   108,
     111,   116,   121,   128,   131,   134,   138,   142,   146,   151,
     156,   161,   166,   170,   176,   181,   186,   190,   195,   200,
     205,   210,   215,   220,   225,   230,   234,   239,   246,   250,
     255,   261,   265,   269,   273,   278,   282,   285,   288,   291,
     294,   296,   300,   303,   307,   312,   314,   317,   321,   322,
     324,   326,   328,   329,   331,   333,   337,   341,   345,   349,
     351,   353,   356,   359,   362,   365,   367,   369,   371,   373,
     375,   377,   379,   381,   385,   389,   392
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      88,     0,    -1,    -1,    96,    -1,     3,    -1,    28,    27,
      -1,    43,    -1,    44,    -1,    11,    26,    -1,    11,    27,
      -1,    93,    35,    92,    26,    -1,    93,    36,    92,    26,
      -1,    37,    92,    26,    -1,    38,    92,    26,    -1,    39,
      92,    26,    -1,    40,    92,    26,    -1,    41,    92,    26,
      -1,    93,     8,    92,    26,    -1,    10,    92,    26,    -1,
      10,    27,    -1,    93,     4,    27,    -1,    93,     4,    17,
      81,    90,    82,    -1,    25,     4,    27,    -1,    25,     4,
      17,    81,    90,    82,    -1,    45,     4,    27,    -1,    46,
       4,    27,    -1,    48,    51,    92,    26,    -1,    49,    51,
      92,    26,    -1,    50,    51,    92,    26,    -1,    52,    26,
      -1,    93,    15,    92,    26,    -1,    93,    15,    17,    71,
      -1,    93,    15,    17,    81,    91,    82,    -1,    30,    26,
      -1,    31,    26,    -1,    32,    92,    26,    -1,    33,    92,
      26,    -1,    53,    67,    54,    -1,    53,    67,    92,    26,
      -1,    53,    67,    55,    94,    -1,    53,    67,    55,    27,
      -1,    53,    56,    92,    26,    -1,    93,    57,    27,    -1,
      93,    58,    27,    83,    26,    -1,    93,    59,    92,    26,
      -1,    94,    95,    92,    26,    -1,    65,    67,    54,    -1,
      65,    67,    92,    26,    -1,    60,    68,    92,    26,    -1,
      61,    68,    92,    26,    -1,    71,    72,    92,    26,    -1,
      71,    73,    92,    26,    -1,    71,    74,    92,    26,    -1,
      71,    75,    92,    26,    -1,    93,    69,    92,    26,    -1,
      93,    70,    27,    -1,    93,    34,    92,    26,    -1,    93,
      34,    17,    81,    91,    82,    -1,    93,    12,    26,    -1,
      93,    14,    27,    27,    -1,    93,    14,    27,    83,    26,
      -1,    93,     5,    26,    -1,    93,    47,    26,    -1,    93,
       6,    27,    -1,     7,    27,    92,    26,    -1,     7,     3,
      26,    -1,    16,    26,    -1,    16,    27,    -1,     9,    26,
      -1,     9,    94,    -1,    27,    -1,    27,    83,    26,    -1,
      90,    27,    -1,    90,    84,    27,    -1,    90,    27,    83,
      26,    -1,    26,    -1,    91,    26,    -1,    91,    84,    26,
      -1,    -1,    21,    -1,    22,    -1,    23,    -1,    -1,    19,
      -1,    20,    -1,    19,    77,    20,    -1,    20,    77,    19,
      -1,    19,    79,    20,    -1,    20,    79,    19,    -1,    17,
      -1,    18,    -1,    17,    19,    -1,    17,    20,    -1,    18,
      19,    -1,    18,    20,    -1,    24,    -1,    25,    -1,    60,
      -1,    61,    -1,    62,    -1,    63,    -1,    64,    -1,    89,
      -1,    96,    77,    96,    -1,    96,    79,    96,    -1,    42,
      96,    -1,    85,    96,    86,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   124,   124,   125,   130,   134,   144,   149,   154,   170,
     185,   203,   220,   224,   228,   232,   236,   240,   272,   280,
     307,   353,   381,   408,   414,   441,   468,   472,   476,   480,
     488,   521,   548,   612,   628,   644,   653,   662,   686,   699,
     719,   743,   756,   807,   897,   935,   975,   993,  1006,  1019,
    1032,  1045,  1058,  1071,  1084,  1122,  1173,  1212,  1276,  1309,
    1399,  1484,  1510,  1543,  1605,  1760,  1774,  1782,  1793,  1802,
    1818,  1861,  1915,  1946,  1978,  2022,  2043,  2054,  2068,  2069,
    2070,  2071,  2075,  2076,  2077,  2078,  2079,  2080,  2081,  2082,
    2083,  2084,  2085,  2086,  2087,  2088,  2089,  2092,  2093,  2096,
    2097,  2098,  2101,  2102,  2103,  2104,  2105
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "ANY", "IP", "IF", "MAC", "MPLS", "TOS",
  "DIR", "FLAGS", "PROTO", "MASK", "HOSTNAME", "NET", "PORT", "FWDSTAT",
  "IN", "OUT", "SRC", "DST", "EQ", "LT", "GT", "PREV", "NEXT", "NUMBER",
  "STRING", "IDENT", "PORTNUM", "ICMP_TYPE", "ICMP_CODE", "ENGINE_TYPE",
  "ENGINE_ID", "AS", "PACKETS", "BYTES", "FLOWS", "PPS", "BPS", "BPP",
  "DURATION", "NOT", "IPV4", "IPV6", "BGPNEXTHOP", "ROUTER", "VLAN",
  "CLIENT", "SERVER", "APP", "LATENCY", "SYSID", "ASA", "REASON", "DENIED",
  "XEVENT", "XIP", "XNET", "XPORT", "INGRESS", "EGRESS", "ACL", "ACE",
  "XACE", "NAT", "ADD", "EVENT", "VRF", "NPORT", "NIP", "PBLOCK", "START",
  "END", "STEP", "SIZE", "'+'", "OR", "'*'", "AND", "NEGATE", "'['", "']'",
  "'/'", "','", "'('", "')'", "$accept", "prog", "term", "iplist",
  "ullist", "comp", "dqual", "inout", "acl", "expr", YY_NULL
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,    43,   331,    42,   332,
     333,    91,    93,    47,    44,    40,    41
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    87,    88,    88,    89,    89,    89,    89,    89,    89,
      89,    89,    89,    89,    89,    89,    89,    89,    89,    89,
      89,    89,    89,    89,    89,    89,    89,    89,    89,    89,
      89,    89,    89,    89,    89,    89,    89,    89,    89,    89,
      89,    89,    89,    89,    89,    89,    89,    89,    89,    89,
      89,    89,    89,    89,    89,    89,    89,    89,    89,    89,
      89,    89,    89,    89,    89,    89,    89,    89,    89,    89,
      90,    90,    90,    90,    90,    91,    91,    91,    92,    92,
      92,    92,    93,    93,    93,    93,    93,    93,    93,    93,
      93,    93,    93,    93,    93,    93,    93,    94,    94,    95,
      95,    95,    96,    96,    96,    96,    96
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     1,     1,     2,     1,     1,     2,     2,
       4,     4,     3,     3,     3,     3,     3,     4,     3,     2,
       3,     6,     3,     6,     3,     3,     4,     4,     4,     2,
       4,     4,     6,     2,     2,     3,     3,     3,     4,     4,
       4,     4,     3,     5,     4,     4,     3,     4,     4,     4,
       4,     4,     4,     4,     4,     3,     4,     6,     3,     4,
       5,     3,     3,     3,     4,     3,     2,     2,     2,     2,
       1,     3,     2,     3,     4,     1,     2,     3,     0,     1,
       1,     1,     0,     1,     1,     3,     3,     3,     3,     1,
       1,     2,     2,     2,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     3,     3,     2,     3
};

/* YYDEFACT[STATE-NAME] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
      82,     4,     0,     0,    78,     0,     0,    89,    90,    83,
      84,    95,    96,     0,     0,     0,    78,    78,    78,    78,
      78,    78,    78,    82,     6,     7,     0,     0,     0,     0,
       0,     0,     0,    97,    98,     0,     0,    82,     0,   102,
       0,     0,     3,     0,    78,    68,    97,    98,    69,    79,
      80,    81,    19,     0,     8,     9,    66,    67,    91,    92,
      93,    94,     0,     0,     0,     0,     0,     5,    33,    34,
       0,     0,     0,     0,     0,     0,     0,   105,     0,     0,
      78,    78,    78,    29,    78,    78,    78,    78,    78,    78,
      78,    78,    78,     0,     1,     0,     0,     0,    78,     0,
       0,    78,    78,    78,    78,     0,     0,     0,    78,    78,
       0,    99,   100,   101,    78,    82,    82,    65,     0,    18,
      85,    87,    86,    88,     0,    22,    35,    36,    12,    13,
      14,    15,    16,    24,    25,     0,     0,     0,     0,    37,
       0,     0,     0,     0,    46,     0,     0,     0,     0,     0,
     106,     0,    20,    61,    63,     0,    58,     0,     0,     0,
       0,     0,     0,     0,    62,    42,     0,     0,     0,    55,
       0,   103,   104,    64,     0,    26,    27,    28,    41,    40,
      39,    38,    48,    49,    47,    50,    51,    52,    53,     0,
      17,    59,     0,    31,     0,    30,     0,    56,    10,    11,
       0,    44,    54,    45,    70,     0,     0,    60,    75,     0,
       0,    43,     0,    72,    23,     0,    21,    76,    32,     0,
      57,    71,     0,    73,    77,    74
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,    38,    39,   205,   209,    53,    40,    41,   114,    42
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -58
static const yytype_int16 yypact[] =
{
     103,   -58,     9,   -16,    32,    16,    31,   119,   142,     2,
      19,   -58,    14,     6,    -1,    12,    86,    86,    86,    86,
      86,    86,    86,   162,   -58,   -58,    44,    47,    17,    34,
      40,    37,   -39,   -57,    36,    33,    85,   162,   105,   -58,
     220,    62,    53,    92,    86,   -58,   -58,   -58,   -58,   -58,
     -58,   -58,   -58,   124,   -58,   -58,   -58,   -58,   -58,   -58,
     -58,   -58,   109,   134,   147,   148,     7,   -58,   -58,   -58,
     144,   149,   150,   151,   157,   158,   159,   -58,   164,   169,
      86,    86,    86,   -58,    86,    -8,    86,    86,    -2,    86,
      86,    86,    86,   -47,   -58,    10,   163,   170,    86,   172,
     182,    39,    94,    86,    86,   187,   189,   190,    86,    86,
     191,   -58,   -58,   -58,    86,   162,   162,   -58,   193,   -58,
     -58,   -58,   -58,   -58,   139,   -58,   -58,   -58,   -58,   -58,
     -58,   -58,   -58,   -58,   -58,   195,   203,   204,   205,   -58,
     -11,   210,   211,   212,   -58,   213,   214,   215,   216,   217,
     -58,   165,   -58,   -58,   -58,   218,   -58,   -19,   -40,   219,
     167,   223,   224,   225,   -58,   -58,   174,   226,   227,   -58,
     232,   180,   -58,   -58,   233,   -58,   -58,   -58,   -58,   -58,
     -58,   -58,   -58,   -58,   -58,   -58,   -58,   -58,   -58,   233,
     -58,   -58,   235,   -58,   236,   -58,   236,   -58,   -58,   -58,
     237,   -58,   -58,   -58,   181,     8,    13,   -58,   -58,    -4,
       0,   -58,   239,   183,   -58,   241,   -58,   -58,   -58,   243,
     -58,   -58,   244,   -58,   -58,   -58
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -58,   -58,   -58,    82,    76,   -15,   -58,    -3,   -58,   -14
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -3
static const yytype_int16 yytable[] =
{
      48,    70,    71,    72,    73,    74,    75,    76,   191,    77,
      45,    86,    43,    49,    50,    51,   179,    84,    66,    49,
      50,    51,   217,    93,   124,    68,   217,   151,    85,   118,
     115,   193,   116,    67,   125,   213,    44,   152,    69,   150,
     213,   194,    54,    55,    46,    47,   139,   140,    78,    46,
      47,    79,   144,    49,    50,    51,   158,    56,    57,    52,
      49,    50,    51,    83,   192,   135,   136,   137,    80,   138,
     141,   142,   143,   145,   146,   147,   148,   149,   218,    62,
     219,    63,   220,   155,   219,    81,   159,   161,   162,   163,
     214,    82,   215,   167,   168,   216,    64,   215,    65,   170,
      88,   171,   172,    -2,    87,    94,     1,    49,    50,    51,
       2,   160,     3,     4,     5,    49,    50,    51,   117,     6,
       7,     8,     9,    10,   111,   112,   113,    11,    12,   120,
     115,    13,   116,    14,    15,    16,    17,   180,    58,    59,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
     119,    28,    29,    30,   121,    31,    32,    89,    90,    91,
      92,    60,    61,    33,    34,     1,   122,   123,    35,     2,
     126,     3,     4,     5,    36,   127,   128,   129,     6,     7,
       8,     9,    10,   130,   131,   132,    11,    12,    37,   153,
      13,   133,    14,    15,    16,    17,   134,   154,   156,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,   157,
      28,    29,    30,   164,    31,    32,   165,   166,   169,   173,
     174,   175,    33,    34,    95,    96,    97,    35,    98,   176,
     177,   178,    99,    36,   100,   101,   181,   182,   183,   184,
     185,   186,   187,   188,   190,   195,   189,    37,   196,   197,
     198,   199,   201,   202,   102,   103,   104,   200,   203,   116,
     204,   207,   208,   211,   212,   221,   222,   105,   223,   224,
     225,   206,   210,     0,     0,     0,     0,   106,   107,   108,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   109,
     110
};

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-58)))

#define yytable_value_is_error(Yytable_value) \
  YYID (0)

static const yytype_int16 yycheck[] =
{
       3,    16,    17,    18,    19,    20,    21,    22,    27,    23,
      26,    68,     3,    21,    22,    23,    27,    56,     4,    21,
      22,    23,    26,    37,    17,    26,    26,    17,    67,    44,
      77,    71,    79,    27,    27,    27,    27,    27,    26,    86,
      27,    81,    26,    27,    60,    61,    54,    55,     4,    60,
      61,     4,    54,    21,    22,    23,    17,    26,    27,    27,
      21,    22,    23,    26,    83,    80,    81,    82,    51,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    82,    77,
      84,    79,    82,    98,    84,    51,   101,   102,   103,   104,
      82,    51,    84,   108,   109,    82,    77,    84,    79,   114,
      67,   115,   116,     0,    68,     0,     3,    21,    22,    23,
       7,    17,     9,    10,    11,    21,    22,    23,    26,    16,
      17,    18,    19,    20,    62,    63,    64,    24,    25,    20,
      77,    28,    79,    30,    31,    32,    33,   140,    19,    20,
      37,    38,    39,    40,    41,    42,    43,    44,    45,    46,
      26,    48,    49,    50,    20,    52,    53,    72,    73,    74,
      75,    19,    20,    60,    61,     3,    19,    19,    65,     7,
      26,     9,    10,    11,    71,    26,    26,    26,    16,    17,
      18,    19,    20,    26,    26,    26,    24,    25,    85,    26,
      28,    27,    30,    31,    32,    33,    27,    27,    26,    37,
      38,    39,    40,    41,    42,    43,    44,    45,    46,    27,
      48,    49,    50,    26,    52,    53,    27,    27,    27,    26,
      81,    26,    60,    61,     4,     5,     6,    65,     8,    26,
      26,    26,    12,    71,    14,    15,    26,    26,    26,    26,
      26,    26,    26,    26,    26,    26,    81,    85,    81,    26,
      26,    26,    26,    26,    34,    35,    36,    83,    26,    79,
      27,    26,    26,    26,    83,    26,    83,    47,    27,    26,
      26,   189,   196,    -1,    -1,    -1,    -1,    57,    58,    59,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    69,
      70
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     3,     7,     9,    10,    11,    16,    17,    18,    19,
      20,    24,    25,    28,    30,    31,    32,    33,    37,    38,
      39,    40,    41,    42,    43,    44,    45,    46,    48,    49,
      50,    52,    53,    60,    61,    65,    71,    85,    88,    89,
      93,    94,    96,     3,    27,    26,    60,    61,    94,    21,
      22,    23,    27,    92,    26,    27,    26,    27,    19,    20,
      19,    20,    77,    79,    77,    79,     4,    27,    26,    26,
      92,    92,    92,    92,    92,    92,    92,    96,     4,     4,
      51,    51,    51,    26,    56,    67,    68,    68,    67,    72,
      73,    74,    75,    96,     0,     4,     5,     6,     8,    12,
      14,    15,    34,    35,    36,    47,    57,    58,    59,    69,
      70,    62,    63,    64,    95,    77,    79,    26,    92,    26,
      20,    20,    19,    19,    17,    27,    26,    26,    26,    26,
      26,    26,    26,    27,    27,    92,    92,    92,    92,    54,
      55,    92,    92,    92,    54,    92,    92,    92,    92,    92,
      86,    17,    27,    26,    27,    92,    26,    27,    17,    92,
      17,    92,    92,    92,    26,    27,    27,    92,    92,    27,
      92,    96,    96,    26,    81,    26,    26,    26,    26,    27,
      94,    26,    26,    26,    26,    26,    26,    26,    26,    81,
      26,    27,    83,    71,    81,    26,    81,    26,    26,    26,
      83,    26,    26,    26,    27,    90,    90,    26,    26,    91,
      91,    26,    83,    27,    82,    84,    82,    26,    82,    84,
      82,    26,    83,    27,    26,    26
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  However,
   YYFAIL appears to be in use.  Nevertheless, it is formally deprecated
   in Bison 2.4.2's NEWS entry, where a plan to phase it out is
   discussed.  */

#define YYFAIL		goto yyerrlab
#if defined YYFAIL
  /* This is here to suppress warnings from the GCC cpp's
     -Wunused-macros.  Normally we don't worry about that warning, but
     some users do, and we want to make it easy for users to remove
     YYFAIL uses, which will produce warnings from Bison 2.5.  */
#endif

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))

/* Error token number */
#define YYTERROR	1
#define YYERRCODE	256


/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */
#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULL, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULL;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - Assume YYFAIL is not used.  It's too flawed to consider.  See
       <http://lists.gnu.org/archive/html/bison-patches/2009-12/msg00024.html>
       for details.  YYERROR is fine as it does not invoke this
       function.
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULL, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YYUSE (yytype);
}




/* The lookahead symbol.  */
int yychar;


#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval YY_INITIAL_VALUE(yyval_default);

/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 3:
/* Line 1787 of yacc.c  */
#line 125 "grammar.y"
    {   
		StartNode = (yyvsp[(1) - (1)].value); 
	}
    break;

  case 4:
/* Line 1787 of yacc.c  */
#line 130 "grammar.y"
    { /* this is an unconditionally true expression, as a filter applies in any case */
		(yyval.param).self = NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE, NULL ); 
	}
    break;

  case 5:
/* Line 1787 of yacc.c  */
#line 134 "grammar.y"
    {	
		if ( !ScreenIdentString((yyvsp[(2) - (2)].s)) ) {
			yyerror("Illegal ident string");
			YYABORT;
		}

		uint32_t	index = AddIdent((yyvsp[(2) - (2)].s));
		(yyval.param).self = NewBlock(0, 0, index, CMP_IDENT, FUNC_NONE, NULL ); 
	}
    break;

  case 6:
/* Line 1787 of yacc.c  */
#line 144 "grammar.y"
    { 
		(yyval.param).self = NewBlock(OffsetRecordFlags, (1LL << ShiftRecordFlags)  & MaskRecordFlags, 
					(0LL << ShiftRecordFlags)  & MaskRecordFlags, CMP_EQ, FUNC_NONE, NULL); 
	}
    break;

  case 7:
/* Line 1787 of yacc.c  */
#line 149 "grammar.y"
    { 
		(yyval.param).self = NewBlock(OffsetRecordFlags, (1LL << ShiftRecordFlags)  & MaskRecordFlags, 
					(1LL << ShiftRecordFlags)  & MaskRecordFlags, CMP_EQ, FUNC_NONE, NULL); 
	}
    break;

  case 8:
/* Line 1787 of yacc.c  */
#line 154 "grammar.y"
    { 
		int64_t	proto;
		proto = (yyvsp[(2) - (2)].value);

		if ( proto > 255 ) {
			yyerror("Protocol number > 255");
			YYABORT;
		}
		if ( proto < 0 ) {
			yyerror("Unknown protocol");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetProto, MaskProto, (proto << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL); 

	}
    break;

  case 9:
/* Line 1787 of yacc.c  */
#line 170 "grammar.y"
    { 
		int64_t	proto;
		proto = Proto_num((yyvsp[(2) - (2)].s));

		if ( proto > 255 ) {
			yyerror("Protocol number > 255");
			YYABORT;
		}
		if ( proto < 0 ) {
			yyerror("Unknown protocol");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetProto, MaskProto, (proto << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL); 
	}
    break;

  case 10:
/* Line 1787 of yacc.c  */
#line 185 "grammar.y"
    { 

		switch ( (yyvsp[(1) - (4)].param).direction ) {
			case DIR_UNSPEC:
			case DIR_IN: 
				(yyval.param).self = NewBlock(OffsetPackets, MaskPackets, (yyvsp[(4) - (4)].value), (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL); 
				break;
			case DIR_OUT: 
				(yyval.param).self = NewBlock(OffsetOutPackets, MaskPackets, (yyvsp[(4) - (4)].value), (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL); 
				break;
			default:
				/* should never happen */
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}
    break;

  case 11:
/* Line 1787 of yacc.c  */
#line 203 "grammar.y"
    {	

		switch ( (yyvsp[(1) - (4)].param).direction ) {
			case DIR_UNSPEC:
			case DIR_IN: 
				(yyval.param).self = NewBlock(OffsetBytes, MaskBytes, (yyvsp[(4) - (4)].value), (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL); 
				break;
			case DIR_OUT: 
				(yyval.param).self = NewBlock(OffsetOutBytes, MaskBytes, (yyvsp[(4) - (4)].value), (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL); 
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}
    break;

  case 12:
/* Line 1787 of yacc.c  */
#line 220 "grammar.y"
    {	
			(yyval.param).self = NewBlock(OffsetAggrFlows, MaskFlows, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_NONE, NULL); 
	}
    break;

  case 13:
/* Line 1787 of yacc.c  */
#line 224 "grammar.y"
    {	
		(yyval.param).self = NewBlock(0, AnyMask, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_PPS, NULL); 
	}
    break;

  case 14:
/* Line 1787 of yacc.c  */
#line 228 "grammar.y"
    {	
		(yyval.param).self = NewBlock(0, AnyMask, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_BPS, NULL); 
	}
    break;

  case 15:
/* Line 1787 of yacc.c  */
#line 232 "grammar.y"
    {	
		(yyval.param).self = NewBlock(0, AnyMask, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_BPP, NULL); 
	}
    break;

  case 16:
/* Line 1787 of yacc.c  */
#line 236 "grammar.y"
    {	
		(yyval.param).self = NewBlock(0, AnyMask, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_DURATION, NULL); 
	}
    break;

  case 17:
/* Line 1787 of yacc.c  */
#line 240 "grammar.y"
    {	
		if ( (yyvsp[(4) - (4)].value) > 255 ) {
			yyerror("TOS must be 0..255");
			YYABORT;
		}

		switch ( (yyvsp[(1) - (4)].param).direction ) {
			case DIR_UNSPEC:
			case SOURCE:
				(yyval.param).self = NewBlock(OffsetTos, MaskTos, ((yyvsp[(4) - (4)].value) << ShiftTos) & MaskTos, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL); 
				break;
			case DESTINATION:
				(yyval.param).self = NewBlock(OffsetDstTos, MaskDstTos, ((yyvsp[(4) - (4)].value) << ShiftDstTos) & MaskDstTos, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL); 
				break;
			case SOURCE_OR_DESTINATION: 
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetTos, MaskTos, ((yyvsp[(4) - (4)].value) << ShiftTos) & MaskTos, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL),
					NewBlock(OffsetDstTos, MaskDstTos, ((yyvsp[(4) - (4)].value) << ShiftDstTos) & MaskDstTos, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL)
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetTos, MaskTos, ((yyvsp[(4) - (4)].value) << ShiftTos) & MaskTos, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL),
					NewBlock(OffsetDstTos, MaskDstTos, ((yyvsp[(4) - (4)].value) << ShiftDstTos) & MaskDstTos, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL)
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
			}
	}
    break;

  case 18:
/* Line 1787 of yacc.c  */
#line 272 "grammar.y"
    {	
		if ( (yyvsp[(3) - (3)].value) > 63 ) {
			yyerror("Flags must be 0..63");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetFlags, MaskFlags, ((yyvsp[(3) - (3)].value) << ShiftFlags) & MaskFlags, (yyvsp[(2) - (3)].param).comp, FUNC_NONE, NULL); 
	}
    break;

  case 19:
/* Line 1787 of yacc.c  */
#line 280 "grammar.y"
    {	
		uint64_t fl = 0;
		int cnt     = 0;
		size_t		len = strlen((yyvsp[(2) - (2)].s));

		if ( len > 7 ) {
			yyerror("Too many flags");
			YYABORT;
		}

		if ( strchr((yyvsp[(2) - (2)].s), 'F') ) { fl |=  1; cnt++; }
		if ( strchr((yyvsp[(2) - (2)].s), 'S') ) { fl |=  2; cnt++; }
		if ( strchr((yyvsp[(2) - (2)].s), 'R') ) { fl |=  4; cnt++; }
		if ( strchr((yyvsp[(2) - (2)].s), 'P') ) { fl |=  8; cnt++; }
		if ( strchr((yyvsp[(2) - (2)].s), 'A') ) { fl |=  16; cnt++; }
		if ( strchr((yyvsp[(2) - (2)].s), 'U') ) { fl |=  32; cnt++; }
		if ( strchr((yyvsp[(2) - (2)].s), 'X') ) { fl =  63; cnt++; }

		if ( cnt != len ) {
			yyerror("Too many flags");
			YYABORT;
		}

		(yyval.param).self = NewBlock(OffsetFlags, (fl << ShiftFlags) & MaskFlags, 
					(fl << ShiftFlags) & MaskFlags, CMP_FLAGS, FUNC_NONE, NULL); 
	}
    break;

  case 20:
/* Line 1787 of yacc.c  */
#line 307 "grammar.y"
    { 	
		int af, bytes, ret;

		ret = parse_ip(&af, (yyvsp[(3) - (3)].s), IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		if ( ret == -2 ) {
			// could not resolv host => 'not any'
			(yyval.param).self = Invert(NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE, NULL )); 
		} else {
			uint64_t offsets[4] = {OffsetSrcIPv6a, OffsetSrcIPv6b, OffsetDstIPv6a, OffsetDstIPv6b };
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			switch ( (yyvsp[(1) - (3)].param).direction ) {
				case SOURCE:
				case DESTINATION:
					(yyval.param).self = ChainHosts(offsets, IPstack, num_ip, (yyvsp[(1) - (3)].param).direction);
					break;
				case DIR_UNSPEC:
				case SOURCE_OR_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					(yyval.param).self = Connect_OR(src, dst);
					} break;
				case SOURCE_AND_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					(yyval.param).self = Connect_AND(src, dst);
					} break;
				default:
					yyerror("This token is not expected here!");
					YYABORT;
	
			} // End of switch

		}
	}
    break;

  case 21:
/* Line 1787 of yacc.c  */
#line 353 "grammar.y"
    { 	

		switch ( (yyvsp[(1) - (6)].param).direction ) {
			case SOURCE:
				(yyval.param).self = NewBlock(OffsetSrcIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) );
				break;
			case DESTINATION:
				(yyval.param).self = NewBlock(OffsetDstIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetSrcIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) ),
					NewBlock(OffsetDstIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) )
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetSrcIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) ),
					NewBlock(OffsetDstIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		}
	}
    break;

  case 22:
/* Line 1787 of yacc.c  */
#line 381 "grammar.y"
    { 	
		int af, bytes, ret;

		ret = parse_ip(&af, (yyvsp[(3) - (3)].s), IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		(yyval.param).self = Connect_AND(
			NewBlock(OffsetNexthopv6b, MaskIPv6, IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
			NewBlock(OffsetNexthopv6a, MaskIPv6, IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
		);
	}
    break;

  case 23:
/* Line 1787 of yacc.c  */
#line 408 "grammar.y"
    { 	

		(yyval.param).self = NewBlock(OffsetNexthopv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) );

	}
    break;

  case 24:
/* Line 1787 of yacc.c  */
#line 414 "grammar.y"
    { 	
		int af, bytes, ret;

		ret = parse_ip(&af, (yyvsp[(3) - (3)].s), IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		(yyval.param).self = Connect_AND(
			NewBlock(OffsetBGPNexthopv6b, MaskIPv6, IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
			NewBlock(OffsetBGPNexthopv6a, MaskIPv6, IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
		);
	}
    break;

  case 25:
/* Line 1787 of yacc.c  */
#line 441 "grammar.y"
    { 	
		int af, bytes, ret;

		ret = parse_ip(&af, (yyvsp[(3) - (3)].s), IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		(yyval.param).self = Connect_AND(
			NewBlock(OffsetRouterv6b, MaskIPv6, IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
			NewBlock(OffsetRouterv6a, MaskIPv6, IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
		);
	}
    break;

  case 26:
/* Line 1787 of yacc.c  */
#line 468 "grammar.y"
    { 	
		(yyval.param).self = NewBlock(OffsetClientLatency, MaskLatency, (yyvsp[(4) - (4)].value), (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL); 
	}
    break;

  case 27:
/* Line 1787 of yacc.c  */
#line 472 "grammar.y"
    { 	
		(yyval.param).self = NewBlock(OffsetServerLatency, MaskLatency, (yyvsp[(4) - (4)].value), (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL); 
	}
    break;

  case 28:
/* Line 1787 of yacc.c  */
#line 476 "grammar.y"
    { 	
		(yyval.param).self = NewBlock(OffsetAppLatency, MaskLatency, (yyvsp[(4) - (4)].value), (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL); 
	}
    break;

  case 29:
/* Line 1787 of yacc.c  */
#line 480 "grammar.y"
    { 	
		if ( (yyvsp[(2) - (2)].value) > 255 ) {
			yyerror("Router SysID expected between be 1..255");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetExporterSysID, MaskExporterSysID, ((yyvsp[(2) - (2)].value) << ShiftExporterSysID) & MaskExporterSysID, CMP_EQ, FUNC_NONE, NULL); 
	}
    break;

  case 30:
/* Line 1787 of yacc.c  */
#line 488 "grammar.y"
    {	
		if ( (yyvsp[(4) - (4)].value) > 65535 ) {
			yyerror("Port outside of range 0..65535");
			YYABORT;
		}

		switch ( (yyvsp[(1) - (4)].param).direction ) {
			case SOURCE:
				(yyval.param).self = NewBlock(OffsetPort, MaskSrcPort, ((yyvsp[(4) - (4)].value) << ShiftSrcPort) & MaskSrcPort, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				(yyval.param).self = NewBlock(OffsetPort, MaskDstPort, ((yyvsp[(4) - (4)].value) << ShiftDstPort) & MaskDstPort, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetPort, MaskSrcPort, ((yyvsp[(4) - (4)].value) << ShiftSrcPort) & MaskSrcPort, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL ),
					NewBlock(OffsetPort, MaskDstPort, ((yyvsp[(4) - (4)].value) << ShiftDstPort) & MaskDstPort, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL )
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetPort, MaskSrcPort, ((yyvsp[(4) - (4)].value) << ShiftSrcPort) & MaskSrcPort, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL ),
					NewBlock(OffsetPort, MaskDstPort, ((yyvsp[(4) - (4)].value) << ShiftDstPort) & MaskDstPort, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End switch

	}
    break;

  case 31:
/* Line 1787 of yacc.c  */
#line 521 "grammar.y"
    {	
#ifdef NSEL
		switch ( (yyvsp[(1) - (4)].param).direction ) {
			case SOURCE:
					(yyval.param).self = NewBlock(OffsetPort, MaskSrcPort, ShiftSrcPort, CMP_EQ, FUNC_PBLOCK, NULL );
				break;
			case DESTINATION:
					(yyval.param).self = NewBlock(OffsetPort, MaskDstPort, ShiftDstPort, CMP_EQ, FUNC_PBLOCK, NULL );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetPort, MaskSrcPort, ShiftSrcPort, CMP_EQ, FUNC_PBLOCK, NULL ),
					NewBlock(OffsetPort, MaskDstPort, ShiftDstPort, CMP_EQ, FUNC_PBLOCK, NULL )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End switch

#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}
    break;

  case 32:
/* Line 1787 of yacc.c  */
#line 548 "grammar.y"
    { 	
		struct ULongListNode *node;
		ULongtree_t *root = NULL;

		if ( (yyvsp[(1) - (6)].param).direction == DIR_UNSPEC || (yyvsp[(1) - (6)].param).direction == SOURCE_OR_DESTINATION || (yyvsp[(1) - (6)].param).direction == SOURCE_AND_DESTINATION ) {
			// src and/or dst port
			// we need a second rbtree due to different shifts for src and dst ports
			root = malloc(sizeof(ULongtree_t));

			struct ULongListNode *n;
			if ( root == NULL) {
				yyerror("malloc() error");
				YYABORT;
			}
			RB_INIT(root);

			RB_FOREACH(node, ULongtree, (ULongtree_t *)(yyvsp[(5) - (6)].list)) {
				if ( node->value > 65535 ) {
					yyerror("Port outside of range 0..65535");
					YYABORT;
				}
				if ((n = malloc(sizeof(struct ULongListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				n->value 	= (node->value << ShiftDstPort) & MaskDstPort;
				node->value = (node->value << ShiftSrcPort) & MaskSrcPort;
				RB_INSERT(ULongtree, root, n);
			}
		}

		switch ( (yyvsp[(1) - (6)].param).direction ) {
			case SOURCE:
				RB_FOREACH(node, ULongtree, (ULongtree_t *)(yyvsp[(5) - (6)].list)) {
					node->value = (node->value << ShiftSrcPort) & MaskSrcPort;
				}
				(yyval.param).self = NewBlock(OffsetPort, MaskSrcPort, 0, CMP_ULLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) );
				break;
			case DESTINATION:
				RB_FOREACH(node, ULongtree, (ULongtree_t *)(yyvsp[(5) - (6)].list)) {
					node->value = (node->value << ShiftDstPort) & MaskDstPort;
				}
				(yyval.param).self = NewBlock(OffsetPort, MaskDstPort, 0, CMP_ULLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetPort, MaskSrcPort, 0, CMP_ULLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) ),
					NewBlock(OffsetPort, MaskDstPort, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetPort, MaskSrcPort, 0, CMP_ULLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) ),
					NewBlock(OffsetPort, MaskDstPort, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}
    break;

  case 33:
/* Line 1787 of yacc.c  */
#line 612 "grammar.y"
    {
		if ( (yyvsp[(2) - (2)].value) > 255 ) {
			yyerror("ICMP tpye of range 0..15");
			YYABORT;
		}
		(yyval.param).self = Connect_AND(
			// imply proto ICMP with a proto ICMP block
			Connect_OR (
				NewBlock(OffsetProto, MaskProto, ((uint64_t)IPPROTO_ICMP << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL), 
				NewBlock(OffsetProto, MaskProto, ((uint64_t)IPPROTO_ICMPV6 << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL)
			),
			NewBlock(OffsetPort, MaskICMPtype, ((yyvsp[(2) - (2)].value) << ShiftICMPtype) & MaskICMPtype, CMP_EQ, FUNC_NONE, NULL )
		);

	}
    break;

  case 34:
/* Line 1787 of yacc.c  */
#line 628 "grammar.y"
    {
		if ( (yyvsp[(2) - (2)].value) > 255 ) {
			yyerror("ICMP code of range 0..15");
			YYABORT;
		}
		(yyval.param).self = Connect_AND(
			// imply proto ICMP with a proto ICMP block
			Connect_OR (
				NewBlock(OffsetProto, MaskProto, ((uint64_t)IPPROTO_ICMP << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL), 
				NewBlock(OffsetProto, MaskProto, ((uint64_t)IPPROTO_ICMPV6 << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL)
			),
			NewBlock(OffsetPort, MaskICMPcode, ((yyvsp[(2) - (2)].value) << ShiftICMPcode) & MaskICMPcode, CMP_EQ, FUNC_NONE, NULL )
		);

	}
    break;

  case 35:
/* Line 1787 of yacc.c  */
#line 644 "grammar.y"
    {
		if ( (yyvsp[(3) - (3)].value) > 255 ) {
			yyerror("Engine type of range 0..255");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetRouterID, MaskEngineType, ((yyvsp[(3) - (3)].value) << ShiftEngineType) & MaskEngineType, (yyvsp[(2) - (3)].param).comp, FUNC_NONE, NULL);

	}
    break;

  case 36:
/* Line 1787 of yacc.c  */
#line 653 "grammar.y"
    {
		if ( (yyvsp[(3) - (3)].value) > 255 ) {
			yyerror("Engine ID of range 0..255");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetRouterID, MaskEngineID, ((yyvsp[(3) - (3)].value) << ShiftEngineID) & MaskEngineID, (yyvsp[(2) - (3)].param).comp, FUNC_NONE, NULL);

	}
    break;

  case 37:
/* Line 1787 of yacc.c  */
#line 662 "grammar.y"
    {
#ifdef NSEL
		if ( strncasecmp((yyvsp[(3) - (3)].s),"ignore", 6) == 0) {
			(yyval.param).self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_IGNORE << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else if( strncasecmp((yyvsp[(3) - (3)].s),"create", 6) == 0) {
			(yyval.param).self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_CREATE << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else if( strncasecmp((yyvsp[(3) - (3)].s),"term", 4) == 0 || strncasecmp((yyvsp[(3) - (3)].s),"delete", 6) == 0) {
			(yyval.param).self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_DELETE << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else if  (strncasecmp((yyvsp[(3) - (3)].s),"deny", 4) == 0) {
			(yyval.param).self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_DENIED << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else if  (strncasecmp((yyvsp[(3) - (3)].s),"alert", 5) == 0) {
			(yyval.param).self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_ALERT << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else if  (strncasecmp((yyvsp[(3) - (3)].s),"update", 6) == 0) {
			(yyval.param).self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_UPDATE << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else {
			yyerror("Unknown asa event");
			YYABORT;
		}
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}
    break;

  case 38:
/* Line 1787 of yacc.c  */
#line 686 "grammar.y"
    {
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 255 ) {
			yyerror("Invalid xevent ID");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetConnID, MaskFWevent, ( (yyvsp[(4) - (4)].value) << ShiftFWevent) & MaskFWevent, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}
    break;

  case 39:
/* Line 1787 of yacc.c  */
#line 699 "grammar.y"
    {
#ifdef NSEL
		uint64_t xevent = 0;
		if ( (yyvsp[(4) - (4)].param).inout == INGRESS ) {
			xevent = 1001;
		} else if ( (yyvsp[(4) - (4)].param).inout == EGRESS ) {
			xevent = 1002;
		} else {
				yyerror("Invalid inout token");
				YYABORT;
		}
		(yyval.param).self = Connect_AND(
			NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_DENIED << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL ),
			NewBlock(OffsetConnID, MaskFWXevent, ( xevent << ShiftFWXevent) & MaskFWXevent, CMP_EQ, FUNC_NONE, NULL )
		);
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}
    break;

  case 40:
/* Line 1787 of yacc.c  */
#line 719 "grammar.y"
    {
#ifdef NSEL
		uint64_t xevent = 0;
		if( strncasecmp((yyvsp[(4) - (4)].s),"interface", 9) == 0) {
			xevent = 1003;
		} else if( strncasecmp((yyvsp[(4) - (4)].s),"nosyn", 5) == 0) {
			xevent = 1004;
		} else {
			xevent = (uint64_t)strtol((yyvsp[(4) - (4)].s), (char **)NULL, 10);
			if ( (xevent == 0 && errno == EINVAL) || xevent > 65535 ) {
				yyerror("Invalid xevent ID");
				YYABORT;
			}
		}
		(yyval.param).self = Connect_AND(
			NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_DENIED << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL ),
			NewBlock(OffsetConnID, MaskFWXevent, ( xevent << ShiftFWXevent) & MaskFWXevent, CMP_EQ, FUNC_NONE, NULL )
		);
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}
    break;

  case 41:
/* Line 1787 of yacc.c  */
#line 743 "grammar.y"
    {
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 65535 ) {
			yyerror("Invalid xevent ID");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetConnID, MaskFWXevent, ( (yyvsp[(4) - (4)].value) << ShiftFWXevent) & MaskFWXevent, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}
    break;

  case 42:
/* Line 1787 of yacc.c  */
#line 756 "grammar.y"
    { 	
#ifdef NSEL
		int af, bytes, ret;

		ret = parse_ip(&af, (yyvsp[(3) - (3)].s), IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		if ( ret == -2 ) {
			// could not resolv host => 'not any'
			(yyval.param).self = Invert(NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE, NULL )); 
		} else {
			uint64_t offsets[4] = {OffsetXLATESRCv6a, OffsetXLATESRCv6b, OffsetXLATEDSTv6a, OffsetXLATEDSTv6b };
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			switch ( (yyvsp[(1) - (3)].param).direction ) {
				case SOURCE:
				case DESTINATION:
					(yyval.param).self = ChainHosts(offsets, IPstack, num_ip, (yyvsp[(1) - (3)].param).direction);
					break;
				case DIR_UNSPEC:
				case SOURCE_OR_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					(yyval.param).self = Connect_OR(src, dst);
					} break;
				case SOURCE_AND_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					(yyval.param).self = Connect_AND(src, dst);
					} break;
				default:
					yyerror("This token is not expected here!");
					YYABORT;
	
			} // End of switch

		}
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}
    break;

  case 43:
/* Line 1787 of yacc.c  */
#line 807 "grammar.y"
    { 
#ifdef NSEL
		int af, bytes, ret;
		uint64_t	mask[2];

		ret = parse_ip(&af, (yyvsp[(3) - (5)].s), IPstack, &bytes, STRICT_IP, &num_ip);
		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set


		if ( (yyvsp[(5) - (5)].value) > (bytes*8) ) {
			yyerror("Too many netbits for this IP addresss");
			YYABORT;
		}

		if ( af == PF_INET ) {
			mask[0] = 0xffffffffffffffffLL;
			mask[1] = 0xffffffffffffffffLL << ( 32 - (yyvsp[(5) - (5)].value) );
		} else {	// PF_INET6
			if ( (yyvsp[(5) - (5)].value) > 64 ) {
				mask[0] = 0xffffffffffffffffLL;
				mask[1] = 0xffffffffffffffffLL << ( 128 - (yyvsp[(5) - (5)].value) );
			} else {
				mask[0] = 0xffffffffffffffffLL << ( 64 - (yyvsp[(5) - (5)].value) );
				mask[1] = 0;
			}
		}
		// IP aadresses are stored in network representation 
		mask[0]	 = mask[0];
		mask[1]	 = mask[1];

		IPstack[0] &= mask[0];
		IPstack[1] &= mask[1];

		switch ( (yyvsp[(1) - (5)].param).direction ) {
			case SOURCE:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetXLATESRCv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATESRCv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetXLATEDSTv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATEDSTv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					Connect_AND(
						NewBlock(OffsetXLATESRCv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetXLATESRCv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetXLATEDSTv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetXLATEDSTv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					Connect_AND(
						NewBlock(OffsetXLATESRCv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetXLATESRCv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetXLATEDSTv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetXLATEDSTv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}
    break;

  case 44:
/* Line 1787 of yacc.c  */
#line 897 "grammar.y"
    {	
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 65535 ) {
			yyerror("Port outside of range 0..65535");
			YYABORT;
		}

		switch ( (yyvsp[(1) - (4)].param).direction ) {
			case SOURCE:
				(yyval.param).self = NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATESRCPORT) & MaskXLATESRCPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				(yyval.param).self = NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATESRCPORT) & MaskXLATESRCPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL )
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATESRCPORT) & MaskXLATESRCPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End switch
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif

	}
    break;

  case 45:
/* Line 1787 of yacc.c  */
#line 935 "grammar.y"
    {
#ifdef NSEL
		uint64_t offset, mask, shift;
		if ( (yyvsp[(1) - (4)].param).inout == INGRESS ) {
			switch ((yyvsp[(2) - (4)].param).acl) {
				case ACL:
					offset = OffsetIngressAclId;
					mask   = MaskIngressAclId;	
					shift  = ShiftIngressAclId;
					break;
				case ACE:
					offset = OffsetIngressAceId;
					mask   = MaskIngressAceId;	
					shift  = ShiftIngressAceId;
					break;
				case XACE:
					offset = OffsetIngressGrpId;
					mask   = MaskIngressGrpId;	
					shift  = ShiftIngressGrpId;
					break;
				default:
					yyerror("Invalid ACL specifier");
					YYABORT;
			}
		} else if ( (yyvsp[(1) - (4)].param).inout == EGRESS && (yyval.param).acl == ACL ) {
			offset = OffsetEgressAclId;
			mask   = MaskEgressAclId;	
			shift  = ShiftEgressAclId;
		} else {
			yyerror("ingress/egress syntax error");
			YYABORT;
		}
		(yyval.param).self = NewBlock(offset, mask, ((yyvsp[(4) - (4)].value) << shift) & mask , (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );

#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}
    break;

  case 46:
/* Line 1787 of yacc.c  */
#line 975 "grammar.y"
    {
#ifdef NSEL
		if ( strncasecmp((yyvsp[(3) - (3)].s),"invalid", 7) == 0) {
			(yyval.param).self = NewBlock(OffsetNATevent, MasNATevent, ( NEL_EVENT_INVALID << ShiftNATevent) & MasNATevent, CMP_EQ, FUNC_NONE, NULL );
		} else if( strncasecmp((yyvsp[(3) - (3)].s),"add", 3) == 0 || strncasecmp((yyvsp[(3) - (3)].s),"create", 6) == 0) {
			(yyval.param).self = NewBlock(OffsetNATevent, MasNATevent, ( NEL_EVENT_ADD << ShiftNATevent) & MasNATevent, CMP_EQ, FUNC_NONE, NULL );
		} else if( strncasecmp((yyvsp[(3) - (3)].s),"delete", 6) == 0) {
			(yyval.param).self = NewBlock(OffsetNATevent, MasNATevent, ( NEL_EVENT_DELETE << ShiftNATevent) & MasNATevent, CMP_EQ, FUNC_NONE, NULL );
		} else {
			yyerror("Unknown nat event");
			YYABORT;
		}
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}
    break;

  case 47:
/* Line 1787 of yacc.c  */
#line 993 "grammar.y"
    {
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 255 ) {
			yyerror("Invalid event ID");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetNATevent, MasNATevent, ( (yyvsp[(4) - (4)].value) << ShiftNATevent) & MasNATevent, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}
    break;

  case 48:
/* Line 1787 of yacc.c  */
#line 1006 "grammar.y"
    {
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 0xFFFFFFFFLL ) {
			yyerror("Invalid ingress vrf ID");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetIVRFID, MaskIVRFID, ( (yyvsp[(4) - (4)].value) << ShiftIVRFID) & MaskIVRFID, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}
    break;

  case 49:
/* Line 1787 of yacc.c  */
#line 1019 "grammar.y"
    {
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 0xFFFFFFFFLL ) {
			yyerror("Invalid egress vrf ID");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetEVRFID, MaskEVRFID, ( (yyvsp[(4) - (4)].value) << ShiftEVRFID) & MaskEVRFID, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}
    break;

  case 50:
/* Line 1787 of yacc.c  */
#line 1032 "grammar.y"
    {
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 65536 ) {
			yyerror("Invalid port");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetPortBlock, MaskPortBlockStart, ( (yyvsp[(4) - (4)].value) << ShiftPortBlockStart) & MaskPortBlockStart, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}
    break;

  case 51:
/* Line 1787 of yacc.c  */
#line 1045 "grammar.y"
    {
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 65536 ) {
			yyerror("Invalid port");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetPortBlock, MaskPortBlockEnd, ( (yyvsp[(4) - (4)].value) << ShiftPortBlockEnd) & MaskPortBlockEnd, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}
    break;

  case 52:
/* Line 1787 of yacc.c  */
#line 1058 "grammar.y"
    {
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 65536 ) {
			yyerror("Invalid port");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetPortBlock, MaskPortBlockStep, ( (yyvsp[(4) - (4)].value) << ShiftPortBlockStep) & MaskPortBlockStep, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}
    break;

  case 53:
/* Line 1787 of yacc.c  */
#line 1071 "grammar.y"
    {
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 65536 ) {
			yyerror("Invalid port");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetPortBlock, MaskPortBlockSize, ( (yyvsp[(4) - (4)].value) << ShiftPortBlockSize) & MaskPortBlockSize, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}
    break;

  case 54:
/* Line 1787 of yacc.c  */
#line 1084 "grammar.y"
    {	
#ifdef NSEL
		if ( (yyvsp[(4) - (4)].value) > 65535 ) {
			yyerror("Port outside of range 0..65535");
			YYABORT;
		}

		switch ( (yyvsp[(1) - (4)].param).direction ) {
			case SOURCE:
				(yyval.param).self = NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATESRCPORT) & MaskXLATESRCPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				(yyval.param).self = NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATESRCPORT) & MaskXLATESRCPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL )
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATESRCPORT) & MaskXLATESRCPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ((yyvsp[(4) - (4)].value) << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End switch
#else
		yyerror("NEL/NAT filters not available");
		YYABORT;
#endif

	}
    break;

  case 55:
/* Line 1787 of yacc.c  */
#line 1122 "grammar.y"
    { 	
#ifdef NSEL
		int af, bytes, ret;

		ret = parse_ip(&af, (yyvsp[(3) - (3)].s), IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		if ( ret == -2 ) {
			// could not resolv host => 'not any'
			(yyval.param).self = Invert(NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE, NULL )); 
		} else {
			uint64_t offsets[4] = {OffsetXLATESRCv6a, OffsetXLATESRCv6b, OffsetXLATEDSTv6a, OffsetXLATEDSTv6b };
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			switch ( (yyvsp[(1) - (3)].param).direction ) {
				case SOURCE:
				case DESTINATION:
					(yyval.param).self = ChainHosts(offsets, IPstack, num_ip, (yyvsp[(1) - (3)].param).direction);
					break;
				case DIR_UNSPEC:
				case SOURCE_OR_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					(yyval.param).self = Connect_OR(src, dst);
					} break;
				case SOURCE_AND_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					(yyval.param).self = Connect_AND(src, dst);
					} break;
				default:
					yyerror("This token is not expected here!");
					YYABORT;
	
			} // End of switch

		}
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}
    break;

  case 56:
/* Line 1787 of yacc.c  */
#line 1173 "grammar.y"
    {	
		if ( (yyvsp[(4) - (4)].value) > 0xfFFFFFFF ) {
			yyerror("AS number of range");
			YYABORT;
		}

		switch ( (yyvsp[(1) - (4)].param).direction ) {
			case SOURCE:
				(yyval.param).self = NewBlock(OffsetAS, MaskSrcAS, ((yyvsp[(4) - (4)].value) << ShiftSrcAS) & MaskSrcAS, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				(yyval.param).self = NewBlock(OffsetAS, MaskDstAS, ((yyvsp[(4) - (4)].value) << ShiftDstAS) & MaskDstAS, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL);
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetAS, MaskSrcAS, ((yyvsp[(4) - (4)].value) << ShiftSrcAS) & MaskSrcAS, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL ),
					NewBlock(OffsetAS, MaskDstAS, ((yyvsp[(4) - (4)].value) << ShiftDstAS) & MaskDstAS, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL)
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetAS, MaskSrcAS, ((yyvsp[(4) - (4)].value) << ShiftSrcAS) & MaskSrcAS, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL ),
					NewBlock(OffsetAS, MaskDstAS, ((yyvsp[(4) - (4)].value) << ShiftDstAS) & MaskDstAS, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL)
				);
				break;
			case ADJ_PREV:
				(yyval.param).self = NewBlock(OffsetBGPadj, MaskBGPadjPrev, ((yyvsp[(4) - (4)].value) << ShiftBGPadjPrev) & MaskBGPadjPrev, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
				break;
			case ADJ_NEXT:
				(yyval.param).self = NewBlock(OffsetBGPadj, MaskBGPadjNext, ((yyvsp[(4) - (4)].value) << ShiftBGPadjNext) & MaskBGPadjNext, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}
    break;

  case 57:
/* Line 1787 of yacc.c  */
#line 1212 "grammar.y"
    { 	
		struct ULongListNode *node;
		ULongtree_t *root = NULL;

		if ( (yyvsp[(1) - (6)].param).direction == DIR_UNSPEC || (yyvsp[(1) - (6)].param).direction == SOURCE_OR_DESTINATION || (yyvsp[(1) - (6)].param).direction == SOURCE_AND_DESTINATION ) {
			// src and/or dst AS
			// we need a second rbtree due to different shifts for src and dst AS
			root = malloc(sizeof(ULongtree_t));

			struct ULongListNode *n;
			if ( root == NULL) {
				yyerror("malloc() error");
				YYABORT;
			}
			RB_INIT(root);

			RB_FOREACH(node, ULongtree, (ULongtree_t *)(yyvsp[(5) - (6)].list)) {
				if ( node->value > 0xFFFFFFFFLL ) {
					yyerror("AS number of range");
					YYABORT;
				}
				if ((n = malloc(sizeof(struct ULongListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				n->value 	= (node->value << ShiftDstAS) & MaskDstAS;
				node->value = (node->value << ShiftSrcAS) & MaskSrcAS;
				RB_INSERT(ULongtree, root, n);
			}
		}

		switch ( (yyvsp[(1) - (6)].param).direction ) {
			case SOURCE:
				RB_FOREACH(node, ULongtree, (ULongtree_t *)(yyvsp[(5) - (6)].list)) {
					node->value = (node->value << ShiftSrcAS) & MaskSrcAS;
				}
				(yyval.param).self = NewBlock(OffsetAS, MaskSrcAS, 0, CMP_ULLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) );
				break;
			case DESTINATION:
				RB_FOREACH(node, ULongtree, (ULongtree_t *)(yyvsp[(5) - (6)].list)) {
					node->value = (node->value << ShiftDstAS) & MaskDstAS;
				}
				(yyval.param).self = NewBlock(OffsetAS, MaskDstAS, 0, CMP_ULLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetAS, MaskSrcAS, 0, CMP_ULLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) ),
					NewBlock(OffsetAS, MaskDstAS, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetAS, MaskSrcAS, 0, CMP_ULLIST, FUNC_NONE, (void *)(yyvsp[(5) - (6)].list) ),
					NewBlock(OffsetAS, MaskDstAS, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		}

	}
    break;

  case 58:
/* Line 1787 of yacc.c  */
#line 1276 "grammar.y"
    {	
		if ( (yyvsp[(3) - (3)].value) > 255 ) {
			yyerror("Mask outside of range 0..255");
			YYABORT;
		}

		switch ( (yyvsp[(1) - (3)].param).direction ) {
			case SOURCE:
				(yyval.param).self = NewBlock(OffsetMask, MaskSrcMask, ((yyvsp[(3) - (3)].value) << ShiftSrcMask) & MaskSrcMask, CMP_EQ, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				(yyval.param).self = NewBlock(OffsetMask, MaskDstMask, ((yyvsp[(3) - (3)].value) << ShiftDstMask) & MaskDstMask, CMP_EQ, FUNC_NONE, NULL );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetMask, MaskSrcMask, ((yyvsp[(3) - (3)].value) << ShiftSrcMask) & MaskSrcMask, CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetMask, MaskDstMask, ((yyvsp[(3) - (3)].value) << ShiftDstMask) & MaskDstMask, CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetMask, MaskSrcMask, ((yyvsp[(3) - (3)].value) << ShiftSrcMask) & MaskSrcMask, CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetMask, MaskDstMask, ((yyvsp[(3) - (3)].value) << ShiftDstMask) & MaskDstMask, CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End switch

	}
    break;

  case 59:
/* Line 1787 of yacc.c  */
#line 1309 "grammar.y"
    { 
		int af, bytes, ret;
		uint64_t	mask[2];
		ret = parse_ip(&af, (yyvsp[(3) - (4)].s), IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af != PF_INET ) {
			yyerror("IP netmask syntax valid only for IPv4");
			YYABORT;
		}
		if ( bytes != 4 ) {
			yyerror("Need complete IP address");
			YYABORT;
		}

		ret = parse_ip(&af, (yyvsp[(4) - (4)].s), mask, &bytes, STRICT_IP, &num_ip);
		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af != PF_INET || bytes != 4 ) {
			yyerror("Invalid netmask for IPv4 address");
			YYABORT;
		}

		IPstack[0] &= mask[0];
		IPstack[1] &= mask[1];

		switch ( (yyvsp[(1) - (4)].param).direction ) {
			case SOURCE:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					Connect_AND(
						NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);		
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					Connect_AND(
						NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);
				break;
			default:
				/* should never happen */
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}
    break;

  case 60:
/* Line 1787 of yacc.c  */
#line 1399 "grammar.y"
    { 
		int af, bytes, ret;
		uint64_t	mask[2];

		ret = parse_ip(&af, (yyvsp[(3) - (5)].s), IPstack, &bytes, STRICT_IP, &num_ip);
		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set


		if ( (yyvsp[(5) - (5)].value) > (bytes*8) ) {
			yyerror("Too many netbits for this IP addresss");
			YYABORT;
		}

		if ( af == PF_INET ) {
			mask[0] = 0xffffffffffffffffLL;
			mask[1] = 0xffffffffffffffffLL << ( 32 - (yyvsp[(5) - (5)].value) );
		} else {	// PF_INET6
			if ( (yyvsp[(5) - (5)].value) > 64 ) {
				mask[0] = 0xffffffffffffffffLL;
				mask[1] = 0xffffffffffffffffLL << ( 128 - (yyvsp[(5) - (5)].value) );
			} else {
				mask[0] = 0xffffffffffffffffLL << ( 64 - (yyvsp[(5) - (5)].value) );
				mask[1] = 0;
			}
		}
		// IP aadresses are stored in network representation 
		mask[0]	 = mask[0];
		mask[1]	 = mask[1];

		IPstack[0] &= mask[0];
		IPstack[1] &= mask[1];

		switch ( (yyvsp[(1) - (5)].param).direction ) {
			case SOURCE:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					Connect_AND(
						NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					Connect_AND(
						NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}
    break;

  case 61:
/* Line 1787 of yacc.c  */
#line 1484 "grammar.y"
    {
		if ( (yyvsp[(3) - (3)].value) > 0xffffffffLL ) {
			yyerror("Input interface number must 0..2^32");
			YYABORT;
		}

		switch ( (yyvsp[(1) - (3)].param).direction ) {
			case DIR_UNSPEC:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetInOut, MaskInput, ((yyvsp[(3) - (3)].value) << ShiftInput) & MaskInput, CMP_EQ, FUNC_NONE, NULL),
					NewBlock(OffsetInOut, MaskOutput, ((yyvsp[(3) - (3)].value) << ShiftOutput) & MaskOutput, CMP_EQ, FUNC_NONE, NULL)
				);
				break;
			case DIR_IN: 
				(yyval.param).self = NewBlock(OffsetInOut, MaskInput, ((yyvsp[(3) - (3)].value) << ShiftInput) & MaskInput, CMP_EQ, FUNC_NONE, NULL); 
				break;
			case DIR_OUT: 
				(yyval.param).self = NewBlock(OffsetInOut, MaskOutput, ((yyvsp[(3) - (3)].value) << ShiftOutput) & MaskOutput, CMP_EQ, FUNC_NONE, NULL); 
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}
    break;

  case 62:
/* Line 1787 of yacc.c  */
#line 1510 "grammar.y"
    {	
		if ( (yyvsp[(3) - (3)].value) > 65535 ) {
			yyerror("VLAN number of range 0..65535");
			YYABORT;
		}

		switch ( (yyvsp[(1) - (3)].param).direction ) {
			case SOURCE:
				(yyval.param).self = NewBlock(OffsetVlan, MaskSrcVlan, ((yyvsp[(3) - (3)].value) << ShiftSrcVlan) & MaskSrcVlan, CMP_EQ, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				(yyval.param).self = NewBlock(OffsetVlan, MaskDstVlan, ((yyvsp[(3) - (3)].value) << ShiftDstVlan) & MaskDstVlan, CMP_EQ, FUNC_NONE, NULL);
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				(yyval.param).self = Connect_OR(
					NewBlock(OffsetVlan, MaskSrcVlan, ((yyvsp[(3) - (3)].value) << ShiftSrcVlan) & MaskSrcVlan, CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetVlan, MaskDstVlan, ((yyvsp[(3) - (3)].value) << ShiftDstVlan) & MaskDstVlan, CMP_EQ, FUNC_NONE, NULL)
				);
				break;
			case SOURCE_AND_DESTINATION:
				(yyval.param).self = Connect_AND(
					NewBlock(OffsetVlan, MaskSrcVlan, ((yyvsp[(3) - (3)].value) << ShiftSrcVlan) & MaskSrcVlan, CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetVlan, MaskDstVlan, ((yyvsp[(3) - (3)].value) << ShiftDstVlan) & MaskDstVlan, CMP_EQ, FUNC_NONE, NULL)
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}
    break;

  case 63:
/* Line 1787 of yacc.c  */
#line 1543 "grammar.y"
    {
		uint64_t	mac = VerifyMac((yyvsp[(3) - (3)].s));
		if ( mac == 0 ) {
			yyerror("Invalid MAC address format");
			YYABORT;
		}
		switch ( (yyvsp[(1) - (3)].param).direction ) {
			case DIR_UNSPEC: {
					uint32_t in, out;
					in  = Connect_OR(
						NewBlock(OffsetInSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetInDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					out  = Connect_OR(
						NewBlock(OffsetOutSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetOutDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					(yyval.param).self = Connect_OR(in, out);
					} break;
			case DIR_IN:
					(yyval.param).self = Connect_OR(
						NewBlock(OffsetInSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetInDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					break;
			case DIR_OUT:
					(yyval.param).self = Connect_OR(
						NewBlock(OffsetOutSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetOutDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					break;
			case SOURCE:
					(yyval.param).self = Connect_OR(
						NewBlock(OffsetInSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetOutSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					break;
			case DESTINATION:
					(yyval.param).self = Connect_OR(
						NewBlock(OffsetInDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetOutDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					break;
			case IN_SRC: 
					(yyval.param).self = NewBlock(OffsetInSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL );
					break;
			case IN_DST: 
					(yyval.param).self = NewBlock(OffsetInDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL );
					break;
			case OUT_SRC: 
					(yyval.param).self = NewBlock(OffsetOutSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL );
					break;
			case OUT_DST:
					(yyval.param).self = NewBlock(OffsetOutDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL );
					break;
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch
	}
    break;

  case 64:
/* Line 1787 of yacc.c  */
#line 1605 "grammar.y"
    {	
		if ( (yyvsp[(4) - (4)].value) > MPLSMAX ) {
			yyerror("MPLS value out of range");
			YYABORT;
		}

		// search for label1 - label10
		if ( strncasecmp((yyvsp[(2) - (4)].s), "label", 5) == 0 ) {
			uint64_t mask;
			uint32_t offset, shift;
			char *s = &(yyvsp[(2) - (4)].s)[5];
			if ( s == '\0' ) {
				yyerror("Missing label number");
				YYABORT;
			}
			int i = (int)strtol(s, (char **)NULL, 10);

			switch (i) {
				case 1:
					offset	= OffsetMPLS12;
					mask	= MaskMPLSlabelOdd;
					shift	= ShiftMPLSlabelOdd;
					break;
				case 2:
					offset	= OffsetMPLS12;
					mask	= MaskMPLSlabelEven;
					shift	= ShiftMPLSlabelEven;
					break;
				case 3:
					offset	= OffsetMPLS34;
					mask	= MaskMPLSlabelOdd;
					shift	= ShiftMPLSlabelOdd;
					break;
				case 4:
					offset	= OffsetMPLS34;
					mask	= MaskMPLSlabelEven;
					shift	= ShiftMPLSlabelEven;
					break;
				case 5:
					offset	= OffsetMPLS56;
					mask	= MaskMPLSlabelOdd;
					shift	= ShiftMPLSlabelOdd;
					break;
				case 6:
					offset	= OffsetMPLS56;
					mask	= MaskMPLSlabelEven;
					shift	= ShiftMPLSlabelEven;
					break;
				case 7:
					offset	= OffsetMPLS78;
					mask	= MaskMPLSlabelOdd;
					shift	= ShiftMPLSlabelOdd;
					break;
				case 8:
					offset	= OffsetMPLS78;
					mask	= MaskMPLSlabelEven;
					shift	= ShiftMPLSlabelEven;
					break;
				case 9:
					offset	= OffsetMPLS910;
					mask	= MaskMPLSlabelOdd;
					shift	= ShiftMPLSlabelOdd;
					break;
				case 10:
					offset	= OffsetMPLS910;
					mask	= MaskMPLSlabelEven;
					shift	= ShiftMPLSlabelEven;
					break;
				default: 
					yyerror("MPLS label out of range 1..10");
					YYABORT;
			}
			(yyval.param).self = NewBlock(offset, mask, ((yyvsp[(4) - (4)].value) << shift) & mask, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );

		} else if ( strcasecmp((yyvsp[(2) - (4)].s), "eos") == 0 ) {
			// match End of Stack label 
			(yyval.param).self = NewBlock(0, AnyMask, (yyvsp[(4) - (4)].value) << 4, (yyvsp[(3) - (4)].param).comp, FUNC_MPLS_EOS, NULL );

		} else if ( strncasecmp((yyvsp[(2) - (4)].s), "exp", 3) == 0 ) {
			uint64_t mask;
			uint32_t offset, shift;
			char *s = &(yyvsp[(2) - (4)].s)[3];
			if ( s == '\0' ) {
				yyerror("Missing label number");
				YYABORT;
			}
			int i = (int)strtol(s, (char **)NULL, 10);

			if ( (yyvsp[(4) - (4)].value) > 7 ) {
				yyerror("MPLS exp value out of range");
				YYABORT;
			}

			switch (i) {
				case 1:
					offset	= OffsetMPLS12;
					mask	= MaskMPLSexpOdd;
					shift	= ShiftMPLSexpOdd;
					break;
				case 2:
					offset	= OffsetMPLS12;
					mask	= MaskMPLSexpEven;
					shift	= ShiftMPLSexpEven;
					break;
				case 3:
					offset	= OffsetMPLS34;
					mask	= MaskMPLSexpOdd;
					shift	= ShiftMPLSexpOdd;
					break;
				case 4:
					offset	= OffsetMPLS34;
					mask	= MaskMPLSexpEven;
					shift	= ShiftMPLSexpEven;
					break;
				case 5:
					offset	= OffsetMPLS56;
					mask	= MaskMPLSexpOdd;
					shift	= ShiftMPLSexpOdd;
					break;
				case 6:
					offset	= OffsetMPLS56;
					mask	= MaskMPLSexpEven;
					shift	= ShiftMPLSexpEven;
					break;
				case 7:
					offset	= OffsetMPLS78;
					mask	= MaskMPLSexpOdd;
					shift	= ShiftMPLSexpOdd;
					break;
				case 8:
					offset	= OffsetMPLS78;
					mask	= MaskMPLSexpEven;
					shift	= ShiftMPLSexpEven;
					break;
				case 9:
					offset	= OffsetMPLS910;
					mask	= MaskMPLSexpOdd;
					shift	= ShiftMPLSexpOdd;
					break;
				case 10:
					offset	= OffsetMPLS910;
					mask	= MaskMPLSexpEven;
					shift	= ShiftMPLSexpEven;
					break;
				default: 
					yyerror("MPLS label out of range 1..10");
					YYABORT;
			}
			(yyval.param).self = NewBlock(offset, mask, (yyvsp[(4) - (4)].value) << shift, (yyvsp[(3) - (4)].param).comp, FUNC_NONE, NULL );

		} else {
			yyerror("Unknown MPLS option");
			YYABORT;
		}
	}
    break;

  case 65:
/* Line 1787 of yacc.c  */
#line 1760 "grammar.y"
    {	
		uint32_t *opt = malloc(sizeof(uint32_t));
		if ( (yyvsp[(3) - (3)].value) > MPLSMAX ) {
			yyerror("MPLS value out of range");
			YYABORT;
		}
		if ( opt == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		*opt = (yyvsp[(3) - (3)].value) << 4;
		(yyval.param).self = NewBlock(0, AnyMask, (yyvsp[(3) - (3)].value) << 4, CMP_EQ, FUNC_MPLS_ANY, opt );

	}
    break;

  case 66:
/* Line 1787 of yacc.c  */
#line 1774 "grammar.y"
    {
		if ( (yyvsp[(2) - (2)].value) > 255 ) {
			yyerror("Forwarding status of range 0..255");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetStatus, MaskStatus, ((yyvsp[(2) - (2)].value) << ShiftStatus) & MaskStatus, CMP_EQ, FUNC_NONE, NULL);
	}
    break;

  case 67:
/* Line 1787 of yacc.c  */
#line 1782 "grammar.y"
    {
		uint64_t id = Get_fwd_status_id((yyvsp[(2) - (2)].s));
		if (id == 256 ) {
			yyerror("Unknown forwarding status");
			YYABORT;
		}

		(yyval.param).self = NewBlock(OffsetStatus, MaskStatus, (id << ShiftStatus) & MaskStatus, CMP_EQ, FUNC_NONE, NULL);

	}
    break;

  case 68:
/* Line 1787 of yacc.c  */
#line 1793 "grammar.y"
    {
		if ( (yyvsp[(2) - (2)].value) > 2 ) {
			yyerror("Flow direction status of range 0, 1");
			YYABORT;
		}
		(yyval.param).self = NewBlock(OffsetDir, MaskDir, ((yyvsp[(2) - (2)].value) << ShiftDir) & MaskDir, CMP_EQ, FUNC_NONE, NULL);

	}
    break;

  case 69:
/* Line 1787 of yacc.c  */
#line 1802 "grammar.y"
    {
		uint64_t dir = 0xFF;
		if ( (yyvsp[(2) - (2)].param).inout == INGRESS )
			dir = 0;
		else if ( (yyvsp[(2) - (2)].param).inout == EGRESS )
			dir = 1;
		else {
			yyerror("Flow direction status of range ingress, egress");
			YYABORT;
		}

		(yyval.param).self = NewBlock(OffsetDir, MaskDir, (dir << ShiftDir) & MaskDir, CMP_EQ, FUNC_NONE, NULL);

	}
    break;

  case 70:
/* Line 1787 of yacc.c  */
#line 1818 "grammar.y"
    { 
		int i, af, bytes, ret;
		struct IPListNode *node;

		IPlist_t *root = malloc(sizeof(IPlist_t));

		if ( root == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		RB_INIT(root);

		ret = parse_ip(&af, (yyvsp[(1) - (1)].s), IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		
		if ( ret != -2 ) {
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			for ( i=0; i<num_ip; i++ ) {
				if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				node->ip[0] = IPstack[2*i];
				node->ip[1] = IPstack[2*i+1];
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL;
				RB_INSERT(IPtree, root, node);
			}

		}
		(yyval.list) = (void *)root;

	}
    break;

  case 71:
/* Line 1787 of yacc.c  */
#line 1861 "grammar.y"
    { 
		int af, bytes, ret;
		struct IPListNode *node;

		IPlist_t *root = malloc(sizeof(IPlist_t));

		if ( root == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		RB_INIT(root);

		ret = parse_ip(&af, (yyvsp[(1) - (3)].s), IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		
		if ( ret != -2 ) {
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
				yyerror("malloc() error");
				YYABORT;
			}

			if ( af == PF_INET ) {
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL << ( 32 - (yyvsp[(3) - (3)].value) );
			} else {	// PF_INET6
				if ( (yyvsp[(3) - (3)].value) > 64 ) {
					node->mask[0] = 0xffffffffffffffffLL;
					node->mask[1] = 0xffffffffffffffffLL << ( 128 - (yyvsp[(3) - (3)].value) );
				} else {
					node->mask[0] = 0xffffffffffffffffLL << ( 64 - (yyvsp[(3) - (3)].value) );
					node->mask[1] = 0;
				}
			}

			node->ip[0] = IPstack[0] & node->mask[0];
			node->ip[1] = IPstack[1] & node->mask[1];

			RB_INSERT(IPtree, root, node);

		}
		(yyval.list) = (void *)root;

	}
    break;

  case 72:
/* Line 1787 of yacc.c  */
#line 1915 "grammar.y"
    { 
		int i, af, bytes, ret;
		struct IPListNode *node;

		ret = parse_ip(&af, (yyvsp[(2) - (2)].s), IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		// ret == - 2 means lookup failure
		if ( ret != -2 ) {
			for ( i=0; i<num_ip; i++ ) {
				if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				node->ip[0] = IPstack[2*i];
				node->ip[1] = IPstack[2*i+1];
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL;
	
				RB_INSERT(IPtree, (IPlist_t *)(yyval.list), node);
			}
		}
	}
    break;

  case 73:
/* Line 1787 of yacc.c  */
#line 1946 "grammar.y"
    { 
		int i, af, bytes, ret;
		struct IPListNode *node;

		ret = parse_ip(&af, (yyvsp[(3) - (3)].s), IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		// ret == - 2 means lookup failure
		if ( ret != -2 ) {
			for ( i=0; i<num_ip; i++ ) {
				if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				node->ip[0] = IPstack[2*i];
				node->ip[1] = IPstack[2*i+1];
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL;
	
				RB_INSERT(IPtree, (IPlist_t *)(yyval.list), node);
			}
		}
	}
    break;

  case 74:
/* Line 1787 of yacc.c  */
#line 1978 "grammar.y"
    { 
		int af, bytes, ret;
		struct IPListNode *node;

		ret = parse_ip(&af, (yyvsp[(2) - (4)].s), IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		// ret == - 2 means lookup failure
		if ( ret != -2 ) {
			if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
				yyerror("malloc() error");
				YYABORT;
			}
			if ( af == PF_INET ) {
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL << ( 32 - (yyvsp[(4) - (4)].value) );
			} else {	// PF_INET6
				if ( (yyvsp[(4) - (4)].value) > 64 ) {
					node->mask[0] = 0xffffffffffffffffLL;
					node->mask[1] = 0xffffffffffffffffLL << ( 128 - (yyvsp[(4) - (4)].value) );
				} else {
					node->mask[0] = 0xffffffffffffffffLL << ( 64 - (yyvsp[(4) - (4)].value) );
					node->mask[1] = 0;
				}
			}

			node->ip[0] = IPstack[0] & node->mask[0];
			node->ip[1] = IPstack[1] & node->mask[1];

			RB_INSERT(IPtree, (IPlist_t *)(yyval.list), node);
		}
	}
    break;

  case 75:
/* Line 1787 of yacc.c  */
#line 2022 "grammar.y"
    { 
		struct ULongListNode *node;

		ULongtree_t *root = malloc(sizeof(ULongtree_t));

		if ( root == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		RB_INIT(root);

		if ((node = malloc(sizeof(struct ULongListNode))) == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		node->value = (yyvsp[(1) - (1)].value);

		RB_INSERT(ULongtree, root, node);
		(yyval.list) = (void *)root;
	}
    break;

  case 76:
/* Line 1787 of yacc.c  */
#line 2043 "grammar.y"
    { 
		struct ULongListNode *node;

		if ((node = malloc(sizeof(struct ULongListNode))) == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		node->value = (yyvsp[(2) - (2)].value);
		RB_INSERT(ULongtree, (ULongtree_t *)(yyval.list), node);
	}
    break;

  case 77:
/* Line 1787 of yacc.c  */
#line 2054 "grammar.y"
    { 
		struct ULongListNode *node;

		if ((node = malloc(sizeof(struct ULongListNode))) == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		node->value = (yyvsp[(3) - (3)].value);
		RB_INSERT(ULongtree, (ULongtree_t *)(yyval.list), node);
	}
    break;

  case 78:
/* Line 1787 of yacc.c  */
#line 2068 "grammar.y"
    { (yyval.param).comp = CMP_EQ; }
    break;

  case 79:
/* Line 1787 of yacc.c  */
#line 2069 "grammar.y"
    { (yyval.param).comp = CMP_EQ; }
    break;

  case 80:
/* Line 1787 of yacc.c  */
#line 2070 "grammar.y"
    { (yyval.param).comp = CMP_LT; }
    break;

  case 81:
/* Line 1787 of yacc.c  */
#line 2071 "grammar.y"
    { (yyval.param).comp = CMP_GT; }
    break;

  case 82:
/* Line 1787 of yacc.c  */
#line 2075 "grammar.y"
    { (yyval.param).direction = DIR_UNSPEC;  			 }
    break;

  case 83:
/* Line 1787 of yacc.c  */
#line 2076 "grammar.y"
    { (yyval.param).direction = SOURCE;				 }
    break;

  case 84:
/* Line 1787 of yacc.c  */
#line 2077 "grammar.y"
    { (yyval.param).direction = DESTINATION;			 }
    break;

  case 85:
/* Line 1787 of yacc.c  */
#line 2078 "grammar.y"
    { (yyval.param).direction = SOURCE_OR_DESTINATION;  }
    break;

  case 86:
/* Line 1787 of yacc.c  */
#line 2079 "grammar.y"
    { (yyval.param).direction = SOURCE_OR_DESTINATION;  }
    break;

  case 87:
/* Line 1787 of yacc.c  */
#line 2080 "grammar.y"
    { (yyval.param).direction = SOURCE_AND_DESTINATION; }
    break;

  case 88:
/* Line 1787 of yacc.c  */
#line 2081 "grammar.y"
    { (yyval.param).direction = SOURCE_AND_DESTINATION; }
    break;

  case 89:
/* Line 1787 of yacc.c  */
#line 2082 "grammar.y"
    { (yyval.param).direction = DIR_IN;				 }
    break;

  case 90:
/* Line 1787 of yacc.c  */
#line 2083 "grammar.y"
    { (yyval.param).direction = DIR_OUT;				 }
    break;

  case 91:
/* Line 1787 of yacc.c  */
#line 2084 "grammar.y"
    { (yyval.param).direction = IN_SRC;				 }
    break;

  case 92:
/* Line 1787 of yacc.c  */
#line 2085 "grammar.y"
    { (yyval.param).direction = IN_DST;				 }
    break;

  case 93:
/* Line 1787 of yacc.c  */
#line 2086 "grammar.y"
    { (yyval.param).direction = OUT_SRC;				 }
    break;

  case 94:
/* Line 1787 of yacc.c  */
#line 2087 "grammar.y"
    { (yyval.param).direction = OUT_DST;				 }
    break;

  case 95:
/* Line 1787 of yacc.c  */
#line 2088 "grammar.y"
    { (yyval.param).direction = ADJ_PREV;				 }
    break;

  case 96:
/* Line 1787 of yacc.c  */
#line 2089 "grammar.y"
    { (yyval.param).direction = ADJ_NEXT;				 }
    break;

  case 97:
/* Line 1787 of yacc.c  */
#line 2092 "grammar.y"
    { (yyval.param).inout	= INGRESS;	}
    break;

  case 98:
/* Line 1787 of yacc.c  */
#line 2093 "grammar.y"
    { (yyval.param).inout	= EGRESS;   }
    break;

  case 99:
/* Line 1787 of yacc.c  */
#line 2096 "grammar.y"
    { (yyval.param).acl = ACL; 	}
    break;

  case 100:
/* Line 1787 of yacc.c  */
#line 2097 "grammar.y"
    { (yyval.param).acl = ACE;		}
    break;

  case 101:
/* Line 1787 of yacc.c  */
#line 2098 "grammar.y"
    { (yyval.param).acl = XACE;	}
    break;

  case 102:
/* Line 1787 of yacc.c  */
#line 2101 "grammar.y"
    { (yyval.value) = (yyvsp[(1) - (1)].param).self;        }
    break;

  case 103:
/* Line 1787 of yacc.c  */
#line 2102 "grammar.y"
    { (yyval.value) = Connect_OR((yyvsp[(1) - (3)].value), (yyvsp[(3) - (3)].value));  }
    break;

  case 104:
/* Line 1787 of yacc.c  */
#line 2103 "grammar.y"
    { (yyval.value) = Connect_AND((yyvsp[(1) - (3)].value), (yyvsp[(3) - (3)].value)); }
    break;

  case 105:
/* Line 1787 of yacc.c  */
#line 2104 "grammar.y"
    { (yyval.value) = Invert((yyvsp[(2) - (2)].value));			}
    break;

  case 106:
/* Line 1787 of yacc.c  */
#line 2105 "grammar.y"
    { (yyval.value) = (yyvsp[(2) - (3)].value); }
    break;


/* Line 1787 of yacc.c  */
#line 4178 "grammar.c"
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


/* Line 2050 of yacc.c  */
#line 2108 "grammar.y"


static void  yyerror(char *msg) {

	if ( FilterFilename )
		snprintf(yyerror_buff, 255 ,"File '%s' line %d: %s at '%s'", FilterFilename, lineno, msg, yytext);
	else 
		snprintf(yyerror_buff, 255, "Line %d: %s at '%s'", lineno, msg, yytext);

	yyerror_buff[255] = '\0';
	fprintf(stderr, "%s\n", yyerror_buff);

} /* End of yyerror */

static uint32_t ChainHosts(uint64_t *offsets, uint64_t *hostlist, int num_records, int type) {
uint32_t offset_a, offset_b, i, j, block;
	if ( type == SOURCE ) {
		offset_a = offsets[0];
		offset_b = offsets[1];
	} else {
		offset_a = offsets[2];
		offset_b = offsets[3];
	}

	i = 0;
	block = Connect_AND(
				NewBlock(offset_b, MaskIPv6, hostlist[i+1] , CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(offset_a, MaskIPv6, hostlist[i] , CMP_EQ, FUNC_NONE, NULL )
			);
	i += 2;
	for ( j=1; j<num_records; j++ ) {
		uint32_t b = Connect_AND(
				NewBlock(offset_b, MaskIPv6, hostlist[i+1] , CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(offset_a, MaskIPv6, hostlist[i] , CMP_EQ, FUNC_NONE, NULL )
			);
		block = Connect_OR(block, b);
		i += 2;
	}

	return block;

} // End of ChainHosts

uint64_t VerifyMac(char *s) {
uint64_t mac;
size_t slen = strlen(s);
long l;
char *p, *q, *r;
int i;

	if ( slen > 17 )
		return 0; 

	for (i=0; i<slen; i++ ) {
		if ( !isxdigit(s[i]) && s[i] != ':' ) 
			return 0;
	}

	p = strdup(s);
	if ( !p ) {
		yyerror("malloc() error");
		return 0;
	}

	mac = 0;
	i = 0;	// number of MAC octets must be 6
	r = p;
	q = strchr(r, ':');
	while ( r && i < 6 ) {
		if ( q ) 
			*q = '\0';
		l = strtol(r, NULL, 16);
		if ( (i == 0 && errno == EINVAL) ) {
			free(p);
			return 0;
		}
		if ( l > 255 ) {
			free(p);
			return 0;
		}

		mac = ( mac << 8 ) | (l & 0xFF );
		i++;

		if ( q ) {
			r = ++q;
			q = strchr(r, ':');
		} else 
			r = NULL;
	}

	if ( i != 6 )
		return 0;

	return mac;

} // End of VerifyMac
