/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

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
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



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




/* Copy the first part of user declarations.  */
#line 31 "filter/grammar.y"


#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "filter.h"
#include "userio.h"
#include "nfxV3.h"
#include "ipconv.h"
#include "sgregex.h"
#include "ja3/ja3.h"
#include "ja4/ja4.h"
#include "nfdump.h"

#define AnyMask 0xffffffffffffffffLL

const data_t NULLPtr = {NULL};

/*
 * function prototypes
 */
static void  yyerror(char *msg, ...);

/* var defs */
extern int 			lineno;
extern char 		*yytext;
extern uint32_t	StartNode;
extern char *FilterFilename;

static ipStack_t ipStack[MAXHOSTS];

static uint32_t ChainHosts(ipStack_t *ipStack, int numIP, int direction);

static int AddIdent(char *ident);

static int AddEngineNum(char *type, uint16_t comp, uint64_t num);

static int AddExporterNum(char *type, uint16_t comp, uint64_t num);

static int AddProto(direction_t direction, char *protoStr, uint64_t protoNum);

static int AddPortNumber(direction_t direction, uint16_t comp, uint64_t port);

static int AddICMP(char *type, uint16_t comp, uint64_t number);

static int AddAsNumber(direction_t direction, uint16_t comp, uint64_t as);

static int AddFlagsNumber(direction_t direction, uint16_t comp, uint64_t flags);

static int AddFlagsString(direction_t direction, char *flags);

static int AddTosNumber(direction_t direction, uint16_t comp, uint64_t tos);

static int AddPackets(direction_t direction, uint16_t comp, uint64_t packets);

static int AddBytes(direction_t direction, uint16_t comp, uint64_t bytes);

static int AddFwdStatNum(uint16_t comp, uint64_t num);

static int AddFwdStatString(char *string);

static int AddIP(direction_t direction, char *IPstr);

static int AddIPlist(direction_t direction, void *IPstr);

static int AddNet(direction_t direction, char *IPstr, char *maskStr);

static int AddNetPrefix(direction_t direction, char *IPstr, uint64_t mask);

static int AddInterfaceNumber(direction_t direction, uint64_t num);

static int AddVlanNumber(direction_t direction, uint64_t num);

static int AddMaskNumber(direction_t direction, uint64_t num);

static int AddFlowDir(direction_t direction, int64_t dirNum);

static int AddMPLS(char *type, uint16_t comp, uint64_t value);

static int AddMAC(direction_t direction, char *macString);

static int AddEthertype(uint64_t etherType);

static int AddLatency(char *type, uint16_t comp, uint64_t number);

static int AddASAString(char *event, char *asaStr);

static int AddASA(char *event, uint16_t comp, uint64_t number);

static int AddASApblock(direction_t direction, char *arg);

static int AddNATString(char *event, char *asaStr);

static int AddNAT(char *event, uint16_t comp, uint64_t number);

static int AddNatPortBlocks(char *type, char *subtype, uint16_t comp, uint64_t number);

static int AddACL(direction_t direction, uint16_t comp, uint64_t number);

static int AddPayload(char *type, char *arg, char *opt);

static int AddGeo(direction_t direction, char *geo);

static int AddObservation(char *type, char *subType, uint16_t comp, uint64_t number);

static int AddVRF(direction_t direction, uint16_t comp, uint64_t number);

static int AddPFString(char *type, char *arg);

static int AddPFNumber(char *type, uint16_t comp, uint64_t number);

static void *NewIplist(char *IPstr, int prefix);

static void *NewU64list(uint64_t num);

static int InsertIPlist(void *IPlist, char *IPstr, int64_t prefix);

static int InsertU64list(void *U64list, uint64_t num);

static int AddPortList(direction_t direction, void *U64List);

static int AddASList(direction_t direction, void *U64List);



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 166 "filter/grammar.y"
{
	uint64_t			value;
	char					*s;
	FilterParam_t	param;
	void					*list;
}
/* Line 193 of yacc.c.  */
#line 374 "filter/grammar.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 387 "filter/grammar.c"

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
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int i)
#else
static int
YYID (i)
    int i;
#endif
{
  return i;
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
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
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
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
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
  yytype_int16 yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  90
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   341

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  77
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  8
/* YYNRULES -- Number of rules.  */
#define YYNRULES  105
/* YYNRULES -- Number of states.  */
#define YYNSTATES  209

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   323

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      75,    76,    68,    66,    74,     2,     2,    71,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    72,     2,    73,     2,     2,     2,     2,     2,     2,
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
      65,    67,    69,    70
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     6,     8,    10,    12,    15,    19,
      23,    27,    32,    37,    41,    45,    49,    54,    58,    62,
      67,    72,    76,    81,    85,    88,    92,    96,   100,   104,
     109,   113,   118,   122,   127,   133,   137,   141,   146,   150,
     153,   156,   159,   164,   169,   173,   178,   182,   186,   191,
     197,   202,   206,   212,   217,   221,   226,   230,   236,   241,
     245,   250,   254,   261,   268,   275,   277,   281,   284,   288,
     293,   295,   298,   302,   303,   305,   307,   309,   311,   313,
     314,   316,   318,   321,   324,   327,   330,   332,   334,   336,
     338,   341,   344,   347,   350,   352,   354,   356,   358,   361,
     363,   365,   367,   371,   375,   378
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      78,     0,    -1,    -1,    84,    -1,     8,    -1,    13,    -1,
      14,    -1,    10,    64,    -1,    11,    82,    65,    -1,    30,
      82,    65,    -1,    31,    82,    65,    -1,    29,    64,    82,
      65,    -1,    32,    64,    82,    65,    -1,    83,    38,    65,
      -1,    83,    38,    64,    -1,    83,    38,    45,    -1,    83,
      39,    82,    65,    -1,    46,    82,    65,    -1,    47,    82,
      65,    -1,    45,    64,    82,    65,    -1,    83,    37,    82,
      65,    -1,    83,    37,    64,    -1,    83,    54,    82,    65,
      -1,    55,    82,    65,    -1,    55,    64,    -1,    33,    82,
      65,    -1,    34,    82,    65,    -1,    35,    82,    65,    -1,
      36,    82,    65,    -1,    83,    48,    82,    65,    -1,    50,
      82,    65,    -1,    83,    49,    82,    65,    -1,    83,    12,
      64,    -1,    83,    15,    64,    64,    -1,    83,    15,    64,
      71,    65,    -1,    83,    41,    65,    -1,    83,    42,    65,
      -1,    83,    40,    82,    65,    -1,    83,    52,    65,    -1,
      51,    65,    -1,    53,    65,    -1,    53,    83,    -1,    43,
      64,    82,    65,    -1,    43,     8,    82,    65,    -1,    83,
      44,    64,    -1,    64,    56,    82,    65,    -1,    57,    64,
      64,    -1,    57,    64,    83,    -1,    57,    64,    82,    65,
      -1,    83,    39,    18,    26,    64,    -1,    83,    58,    82,
      65,    -1,    26,    64,    64,    -1,    26,    64,    64,    82,
      65,    -1,    26,    64,    82,    65,    -1,    59,    64,    64,
      -1,    59,    64,    64,    64,    -1,    83,    60,    64,    -1,
      62,    64,    64,    82,    65,    -1,    83,    61,    82,    65,
      -1,    63,    64,    64,    -1,    63,    64,    82,    65,    -1,
      63,    64,    83,    -1,    83,    12,    18,    72,    80,    73,
      -1,    83,    39,    18,    72,    81,    73,    -1,    83,    40,
      18,    72,    81,    73,    -1,    64,    -1,    64,    71,    65,
      -1,    80,    64,    -1,    80,    74,    64,    -1,    80,    64,
      71,    65,    -1,    65,    -1,    81,    65,    -1,    81,    74,
      65,    -1,    -1,     3,    -1,     4,    -1,     5,    -1,     6,
      -1,     7,    -1,    -1,    16,    -1,    17,    -1,    16,    26,
      -1,    17,    26,    -1,    16,    28,    -1,    17,    28,    -1,
      26,    -1,    28,    -1,    18,    -1,    19,    -1,    18,    16,
      -1,    18,    17,    -1,    19,    16,    -1,    19,    17,    -1,
      24,    -1,    25,    -1,    20,    -1,    21,    -1,    22,    21,
      -1,    23,    -1,    32,    -1,    79,    -1,    84,    67,    84,
      -1,    84,    69,    84,    -1,     9,    84,    -1,    75,    84,
      76,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   195,   195,   196,   201,   206,   210,   214,   218,   222,
     226,   230,   234,   238,   242,   246,   250,   254,   258,   262,
     266,   270,   274,   278,   282,   286,   290,   294,   298,   302,
     306,   310,   314,   318,   322,   326,   330,   334,   338,   342,
     346,   350,   354,   358,   362,   366,   370,   374,   389,   393,
     397,   401,   405,   409,   413,   417,   421,   425,   429,   433,
     437,   441,   459,   463,   467,   473,   477,   481,   485,   489,
     494,   498,   502,   508,   509,   510,   511,   512,   513,   517,
     518,   519,   520,   521,   522,   523,   524,   525,   526,   527,
     528,   529,   530,   531,   532,   533,   534,   535,   536,   537,
     538,   541,   542,   543,   544,   545
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "EQ", "LT", "GT", "LE", "GE", "ANY",
  "NOT", "IDENT", "COUNT", "IP", "IPV4", "IPV6", "NET", "SRC", "DST", "IN",
  "OUT", "PREV", "NEXT", "BGP", "ROUTER", "INGRESS", "EGRESS", "NAT",
  "XLATE", "TUN", "ENGINE", "ENGINETYPE", "ENGINEID", "EXPORTER",
  "DURATION", "PPS", "BPS", "BPP", "FLAGS", "PROTO", "PORT", "AS", "IF",
  "VLAN", "MPLS", "MAC", "ICMP", "ICMPTYPE", "ICMPCODE", "PACKETS",
  "BYTES", "FLOWS", "ETHERTYPE", "MASK", "FLOWDIR", "TOS", "FWDSTAT",
  "LATENCY", "ASA", "ACL", "PAYLOAD", "GEO", "VRF", "OBSERVATION", "PF",
  "STRING", "NUMBER", "'+'", "OR", "'*'", "AND", "NEGATE", "'/'", "'['",
  "']'", "','", "'('", "')'", "$accept", "prog", "term", "iplist",
  "u64list", "comp", "dqual", "expr", 0
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
     315,   316,   317,   318,   319,   320,    43,   321,    42,   322,
     323,    47,    91,    93,    44,    40,    41
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    77,    78,    78,    79,    79,    79,    79,    79,    79,
      79,    79,    79,    79,    79,    79,    79,    79,    79,    79,
      79,    79,    79,    79,    79,    79,    79,    79,    79,    79,
      79,    79,    79,    79,    79,    79,    79,    79,    79,    79,
      79,    79,    79,    79,    79,    79,    79,    79,    79,    79,
      79,    79,    79,    79,    79,    79,    79,    79,    79,    79,
      79,    79,    79,    79,    79,    80,    80,    80,    80,    80,
      81,    81,    81,    82,    82,    82,    82,    82,    82,    83,
      83,    83,    83,    83,    83,    83,    83,    83,    83,    83,
      83,    83,    83,    83,    83,    83,    83,    83,    83,    83,
      83,    84,    84,    84,    84,    84
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     1,     1,     1,     1,     2,     3,     3,
       3,     4,     4,     3,     3,     3,     4,     3,     3,     4,
       4,     3,     4,     3,     2,     3,     3,     3,     3,     4,
       3,     4,     3,     4,     5,     3,     3,     4,     3,     2,
       2,     2,     4,     4,     3,     4,     3,     3,     4,     5,
       4,     3,     5,     4,     3,     4,     3,     5,     4,     3,
       4,     3,     6,     6,     6,     1,     3,     2,     3,     4,
       1,     2,     3,     0,     1,     1,     1,     1,     1,     0,
       1,     1,     2,     2,     2,     2,     1,     1,     1,     1,
       2,     2,     2,     2,     1,     1,     1,     1,     2,     1,
       1,     1,     3,     3,     2,     3
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
      79,     4,    79,     0,    73,     5,     6,    80,    81,    88,
      89,    96,    97,     0,    99,    94,    95,    86,    87,     0,
      73,    73,   100,    73,    73,    73,    73,     0,     0,    73,
      73,    73,     0,    79,    73,     0,     0,     0,     0,     0,
      79,     0,   101,     0,     3,   104,     7,    74,    75,    76,
      77,    78,     0,    82,    84,    83,    85,    90,    91,    92,
      93,    98,    73,    73,     0,     0,    73,     0,     0,     0,
       0,    73,    73,    73,     0,     0,     0,    39,    86,   100,
      40,    41,    24,     0,    79,     0,     0,    79,    73,     0,
       1,     0,     0,    73,     0,    73,    73,     0,     0,     0,
      73,    73,     0,    73,    73,     0,    73,    79,    79,     8,
      51,     0,     0,     9,    10,     0,    25,    26,    27,    28,
       0,     0,     0,    17,    18,    30,    23,    46,     0,    47,
      54,    73,    59,     0,    61,     0,   105,     0,    32,     0,
      21,     0,    15,    14,    13,     0,     0,     0,     0,    35,
      36,    44,     0,     0,    38,     0,     0,    56,     0,   102,
     103,     0,    53,    11,    12,    43,    42,    19,    48,    55,
       0,    60,    45,     0,    33,     0,    20,     0,     0,    16,
       0,    37,    29,    31,    22,    50,    58,    52,    57,    65,
       0,    34,    49,    70,     0,     0,     0,    67,    62,     0,
      71,    63,     0,    64,    66,     0,    68,    72,    69
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,    41,    42,   190,   194,    52,    43,    44
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -53
static const yytype_int16 yypact[] =
{
     104,   -53,   164,   -51,   281,   -53,   -53,    21,    22,    71,
      86,   -53,   -53,    23,   -53,   -53,   -53,    -3,   -53,     1,
     281,   281,     7,   281,   281,   281,   281,    -1,    32,   281,
     281,   281,    40,   276,    52,    42,    45,    46,    55,    75,
     164,   141,   -53,   222,    -7,   -53,   -53,   -53,   -53,   -53,
     -53,   -53,    77,   -53,   -53,   -53,   -53,   -53,   -53,   -53,
     -53,   -53,    88,   281,    78,    79,   281,    81,    83,    91,
      95,   281,   281,   281,   111,   126,   143,   -53,   -53,   -53,
     -53,   -53,   -53,   147,    13,    89,   105,   226,   281,     3,
     -53,   -10,   142,    94,   100,   198,   306,   148,   153,   156,
     281,   281,   157,   281,   281,   160,   281,   164,   164,   -53,
      20,   170,   171,   -53,   -53,   173,   -53,   -53,   -53,   -53,
     175,   176,   188,   -53,   -53,   -53,   -53,   -53,   190,   -53,
     161,   281,   -53,   191,   -53,   192,   -53,   193,   -53,    18,
     -53,   202,   -53,   -53,   -53,     2,   203,   200,   208,   -53,
     -53,   -53,   210,   214,   -53,   216,   224,   -53,   238,   236,
     -53,   241,   -53,   -53,   -53,   -53,   -53,   -53,   -53,   -53,
     242,   -53,   -53,   250,   -53,   251,   -53,   253,   254,   -53,
     254,   -53,   -53,   -53,   -53,   -53,   -53,   -53,   -53,   244,
     -52,   -53,   -53,   -53,    97,   204,   255,   247,   -53,   257,
     -53,   -53,   258,   -53,   -53,   260,   -53,   -53,   -53
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -53,   -53,   -53,   -53,   146,   -20,   -18,     0
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -74
static const yytype_int16 yytable[] =
{
      64,    65,    45,    67,    68,    69,    70,    71,   137,    74,
      75,    76,   197,    46,    83,    81,    47,    48,    49,    50,
      51,   198,   199,    47,    48,    49,    50,    51,   177,     7,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    78,
      89,    18,   111,   112,    61,    79,   115,    53,    55,    54,
      56,   120,   121,   122,   138,    47,    48,    49,    50,    51,
     107,    62,   108,    72,   128,    63,   129,   133,   135,   134,
     107,    66,   108,   141,   178,   146,   148,   127,   -73,   136,
     152,   153,   174,   155,   156,   -73,   158,    57,    58,   175,
     161,    47,    48,    49,    50,    51,    73,    47,    48,    49,
      50,    51,    59,    60,    -2,    77,    84,   159,   160,    85,
      86,   170,     1,     2,     3,     4,    82,     5,     6,    87,
       7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    88,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    90,   109,   113,   114,   142,   116,    27,   117,    28,
      29,    30,   110,   130,    31,    32,   118,    33,   140,    34,
     119,    35,   200,    36,   143,   144,    37,    38,    39,   131,
     201,   202,     1,     2,     3,     4,   123,     5,     6,    40,
       7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,   124,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    47,    48,    49,    50,    51,   139,    27,   125,    28,
      29,    30,   126,   149,    31,    32,   145,    33,   150,    34,
     151,    35,   154,    36,   157,   169,    37,    38,    39,    47,
      48,    49,    50,    51,    91,   162,   163,    92,   164,    40,
     165,   166,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    78,   167,    18,   168,   171,   172,    79,    93,
      94,    95,    96,    97,    98,   173,    99,   176,   179,   200,
     100,   101,   180,   181,   102,   182,   103,   203,   202,   183,
     104,   184,   105,   106,    47,    48,    49,    50,    51,   185,
     132,   -73,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    78,   186,    18,   108,   187,   188,    79,    47,
      48,    49,    50,    51,   189,   196,   191,   192,   205,   193,
     204,   206,     0,   207,   147,   208,   195,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    80
};

static const yytype_int16 yycheck[] =
{
      20,    21,     2,    23,    24,    25,    26,     8,    18,    29,
      30,    31,    64,    64,    34,    33,     3,     4,     5,     6,
       7,    73,    74,     3,     4,     5,     6,     7,    26,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      40,    28,    62,    63,    21,    32,    66,    26,    26,    28,
      28,    71,    72,    73,    64,     3,     4,     5,     6,     7,
      67,    64,    69,    64,    84,    64,    84,    87,    88,    87,
      67,    64,    69,    93,    72,    95,    96,    64,    65,    76,
     100,   101,    64,   103,   104,    65,   106,    16,    17,    71,
     110,     3,     4,     5,     6,     7,    64,     3,     4,     5,
       6,     7,    16,    17,     0,    65,    64,   107,   108,    64,
      64,   131,     8,     9,    10,    11,    64,    13,    14,    64,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    56,    28,    29,    30,    31,    32,    33,    34,    35,
      36,     0,    65,    65,    65,    45,    65,    43,    65,    45,
      46,    47,    64,    64,    50,    51,    65,    53,    64,    55,
      65,    57,    65,    59,    64,    65,    62,    63,    64,    64,
      73,    74,     8,     9,    10,    11,    65,    13,    14,    75,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    65,    28,    29,    30,    31,    32,    33,    34,    35,
      36,     3,     4,     5,     6,     7,    64,    43,    65,    45,
      46,    47,    65,    65,    50,    51,    18,    53,    65,    55,
      64,    57,    65,    59,    64,    64,    62,    63,    64,     3,
       4,     5,     6,     7,    12,    65,    65,    15,    65,    75,
      65,    65,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    65,    28,    65,    65,    65,    32,    37,
      38,    39,    40,    41,    42,    72,    44,    65,    65,    65,
      48,    49,    72,    65,    52,    65,    54,    73,    74,    65,
      58,    65,    60,    61,     3,     4,     5,     6,     7,    65,
      64,    65,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    65,    28,    69,    65,    65,    32,     3,
       4,     5,     6,     7,    64,    71,    65,    64,    71,    65,
      65,    64,    -1,    65,    18,    65,   180,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    65
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     8,     9,    10,    11,    13,    14,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    43,    45,    46,
      47,    50,    51,    53,    55,    57,    59,    62,    63,    64,
      75,    78,    79,    83,    84,    84,    64,     3,     4,     5,
       6,     7,    82,    26,    28,    26,    28,    16,    17,    16,
      17,    21,    64,    64,    82,    82,    64,    82,    82,    82,
      82,     8,    64,    64,    82,    82,    82,    65,    26,    32,
      65,    83,    64,    82,    64,    64,    64,    64,    56,    84,
       0,    12,    15,    37,    38,    39,    40,    41,    42,    44,
      48,    49,    52,    54,    58,    60,    61,    67,    69,    65,
      64,    82,    82,    65,    65,    82,    65,    65,    65,    65,
      82,    82,    82,    65,    65,    65,    65,    64,    82,    83,
      64,    64,    64,    82,    83,    82,    76,    18,    64,    64,
      64,    82,    45,    64,    65,    18,    82,    18,    82,    65,
      65,    64,    82,    82,    65,    82,    82,    64,    82,    84,
      84,    82,    65,    65,    65,    65,    65,    65,    65,    64,
      82,    65,    65,    72,    64,    71,    65,    26,    72,    65,
      72,    65,    65,    65,    65,    65,    65,    65,    65,    64,
      80,    65,    64,    65,    81,    81,    71,    64,    73,    74,
      65,    73,    74,    73,    65,    71,    64,    65,    65
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
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
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
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
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
yy_stack_print (yytype_int16 *bottom, yytype_int16 *top)
#else
static void
yy_stack_print (bottom, top)
    yytype_int16 *bottom;
    yytype_int16 *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
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
      fprintf (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      fprintf (stderr, "\n");
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

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
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

  switch (yytype)
    {

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

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



/* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

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
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;
#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  yytype_int16 yyssa[YYINITDEPTH];
  yytype_int16 *yyss = yyssa;
  yytype_int16 *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

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
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

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

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     look-ahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to look-ahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
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
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

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
#line 196 "filter/grammar.y"
    {   
		StartNode = (yyvsp[(1) - (1)].value); 
	}
    break;

  case 4:
#line 201 "filter/grammar.y"
    { /* this is an unconditionally true expression, as a filter applies in any case */
		data_t data = {.dataVal=1};
		(yyval.param).self = NewElement(EXnull, 0, 0, 0, CMP_EQ, FUNC_NONE, data);
	}
    break;

  case 5:
#line 206 "filter/grammar.y"
    { 
		(yyval.param).self = NewElement(EXipv4FlowID, OFFsrc4Addr, 0, 0, CMP_EQ, FUNC_NONE, NULLPtr); 
	}
    break;

  case 6:
#line 210 "filter/grammar.y"
    { 
		(yyval.param).self = NewElement(EXipv6FlowID, OFFsrc6Addr, 0, 0, CMP_EQ, FUNC_NONE, NULLPtr); 
	}
    break;

  case 7:
#line 214 "filter/grammar.y"
    {
	  (yyval.param).self  = AddIdent((yyvsp[(2) - (2)].s)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 8:
#line 218 "filter/grammar.y"
    {
		(yyval.param).self = NewElement(EXlocal, OFFflowCount, SIZEflowCount, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_NONE, NULLPtr); 
	}
    break;

  case 9:
#line 222 "filter/grammar.y"
    {
	  (yyval.param).self  = AddEngineNum("type", (yyvsp[(2) - (3)].param).comp, (yyvsp[(3) - (3)].value)); if ( (yyval.param).self < 0 ) YYABORT;
        }
    break;

  case 10:
#line 226 "filter/grammar.y"
    {
	  (yyval.param).self  = AddEngineNum("id", (yyvsp[(2) - (3)].param).comp, (yyvsp[(3) - (3)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 11:
#line 230 "filter/grammar.y"
    {
		(yyval.param).self  = AddEngineNum((yyvsp[(2) - (4)].s), (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 12:
#line 234 "filter/grammar.y"
    {
	  (yyval.param).self  = AddExporterNum((yyvsp[(2) - (4)].s), (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT;
  }
    break;

  case 13:
#line 238 "filter/grammar.y"
    { 
		(yyval.param).self = AddProto((yyvsp[(1) - (3)].param).direction, NULL, (yyvsp[(3) - (3)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 14:
#line 242 "filter/grammar.y"
    {
		(yyval.param).self = AddProto((yyvsp[(1) - (3)].param).direction, (yyvsp[(3) - (3)].s), 0); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 15:
#line 246 "filter/grammar.y"
    {
		(yyval.param).self = AddProto((yyvsp[(1) - (3)].param).direction, "icmp", 0); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 16:
#line 250 "filter/grammar.y"
    {
		(yyval.param).self = AddPortNumber((yyvsp[(1) - (4)].param).direction, (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 17:
#line 254 "filter/grammar.y"
    {
		(yyval.param).self = AddICMP("type", (yyvsp[(2) - (3)].param).comp, (yyvsp[(3) - (3)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 18:
#line 258 "filter/grammar.y"
    {
		(yyval.param).self = AddICMP("code", (yyvsp[(2) - (3)].param).comp, (yyvsp[(3) - (3)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 19:
#line 262 "filter/grammar.y"
    {
		(yyval.param).self  = AddICMP((yyvsp[(2) - (4)].s), (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 20:
#line 266 "filter/grammar.y"
    {
		(yyval.param).self = AddFlagsNumber((yyvsp[(1) - (4)].param).direction, (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 21:
#line 270 "filter/grammar.y"
    {
		(yyval.param).self = AddFlagsString((yyvsp[(1) - (3)].param).direction, (yyvsp[(3) - (3)].s)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 22:
#line 274 "filter/grammar.y"
    {
	  (yyval.param).self = AddTosNumber((yyvsp[(1) - (4)].param).direction, (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 23:
#line 278 "filter/grammar.y"
    {
	  (yyval.param).self = AddFwdStatNum((yyvsp[(2) - (3)].param).comp, (yyvsp[(3) - (3)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 24:
#line 282 "filter/grammar.y"
    {
	  (yyval.param).self = AddFwdStatString((yyvsp[(2) - (2)].s)); if ( (yyval.param).self < 0 ) YYABORT;
        }
    break;

  case 25:
#line 286 "filter/grammar.y"
    {
		(yyval.param).self = NewElement(EXgenericFlowID, 0, SIZEmsecLast, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_DURATION, NULLPtr); 
	}
    break;

  case 26:
#line 290 "filter/grammar.y"
    {
		(yyval.param).self = NewElement(EXgenericFlowID, 0, SIZEmsecLast, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_PPS, NULLPtr);
	}
    break;

  case 27:
#line 294 "filter/grammar.y"
    {
		(yyval.param).self = NewElement(EXgenericFlowID, 0, SIZEmsecLast, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_BPS, NULLPtr);
	}
    break;

  case 28:
#line 298 "filter/grammar.y"
    {
		(yyval.param).self = NewElement(EXgenericFlowID, 0, SIZEmsecLast, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_BPP, NULLPtr); 
	}
    break;

  case 29:
#line 302 "filter/grammar.y"
    {
		(yyval.param).self = AddPackets((yyvsp[(1) - (4)].param).direction, (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 30:
#line 306 "filter/grammar.y"
    {
		(yyval.param).self = NewElement(EXcntFlowID, OFFflows, SIZEflows, (yyvsp[(3) - (3)].value), (yyvsp[(2) - (3)].param).comp, FUNC_NONE, NULLPtr); 
	}
    break;

  case 31:
#line 310 "filter/grammar.y"
    {
		(yyval.param).self = AddBytes((yyvsp[(1) - (4)].param).direction, (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 32:
#line 314 "filter/grammar.y"
    { 	
		(yyval.param).self = AddIP((yyvsp[(1) - (3)].param).direction, (yyvsp[(3) - (3)].s)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 33:
#line 318 "filter/grammar.y"
    {
		(yyval.param).self = AddNet((yyvsp[(1) - (4)].param).direction, (yyvsp[(3) - (4)].s), (yyvsp[(4) - (4)].s)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 34:
#line 322 "filter/grammar.y"
    {
		(yyval.param).self = AddNetPrefix((yyvsp[(1) - (5)].param).direction, (yyvsp[(3) - (5)].s), (yyvsp[(5) - (5)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 35:
#line 326 "filter/grammar.y"
    {
		(yyval.param).self = AddInterfaceNumber((yyvsp[(1) - (3)].param).direction, (yyvsp[(3) - (3)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 36:
#line 330 "filter/grammar.y"
    {
		(yyval.param).self = AddVlanNumber((yyvsp[(1) - (3)].param).direction, (yyvsp[(3) - (3)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 37:
#line 334 "filter/grammar.y"
    {
		(yyval.param).self = AddAsNumber((yyvsp[(1) - (4)].param).direction, (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 38:
#line 338 "filter/grammar.y"
    {
		(yyval.param).self = AddMaskNumber((yyvsp[(1) - (3)].param).direction, (yyvsp[(3) - (3)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 39:
#line 342 "filter/grammar.y"
    {
		(yyval.param).self = AddEthertype((yyvsp[(2) - (2)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 40:
#line 346 "filter/grammar.y"
    {
		(yyval.param).self = AddFlowDir(DIR_UNSPEC, (yyvsp[(2) - (2)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 41:
#line 350 "filter/grammar.y"
    {
		(yyval.param).self = AddFlowDir((yyvsp[(2) - (2)].param).direction, -1); if ( (yyval.param).self < 0 ) YYABORT;
        }
    break;

  case 42:
#line 354 "filter/grammar.y"
    {	
		(yyval.param).self = AddMPLS((yyvsp[(2) - (4)].s), (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 43:
#line 358 "filter/grammar.y"
    {	
		(yyval.param).self = AddMPLS("any", (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 44:
#line 362 "filter/grammar.y"
    {	
		(yyval.param).self = AddMAC((yyvsp[(1) - (3)].param).direction, (yyvsp[(3) - (3)].s)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 45:
#line 366 "filter/grammar.y"
    {
		(yyval.param).self = AddLatency((yyvsp[(1) - (4)].s), (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 46:
#line 370 "filter/grammar.y"
    {
		(yyval.param).self = AddASAString((yyvsp[(2) - (3)].s), (yyvsp[(3) - (3)].s)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 47:
#line 374 "filter/grammar.y"
    {
		switch ((yyvsp[(3) - (3)].param).direction) {
			case DIR_INGRESS:
				(yyval.param).self = AddASAString((yyvsp[(2) - (3)].s), "ingress");
				break;
			case DIR_EGRESS:
				(yyval.param).self = AddASAString((yyvsp[(2) - (3)].s), "egress");
				break;
			default:
				(yyval.param).self = -1;
				yyerror("Unknown direction specifier");
		}
		if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 48:
#line 389 "filter/grammar.y"
    {
		(yyval.param).self = AddASA((yyvsp[(2) - (4)].s), (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 49:
#line 393 "filter/grammar.y"
    {
		(yyval.param).self = AddASApblock((yyvsp[(1) - (5)].param).direction, (yyvsp[(5) - (5)].s)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 50:
#line 397 "filter/grammar.y"
    {
		(yyval.param).self = AddACL((yyvsp[(1) - (4)].param).direction, (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 51:
#line 401 "filter/grammar.y"
    {
		(yyval.param).self = AddNATString((yyvsp[(2) - (3)].s), (yyvsp[(3) - (3)].s)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 52:
#line 405 "filter/grammar.y"
    {
		(yyval.param).self = AddNatPortBlocks((yyvsp[(2) - (5)].s), (yyvsp[(3) - (5)].s), (yyvsp[(4) - (5)].param).comp, (yyvsp[(5) - (5)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 53:
#line 409 "filter/grammar.y"
    {
		(yyval.param).self = AddNAT((yyvsp[(2) - (4)].s), (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT; 
	}
    break;

  case 54:
#line 413 "filter/grammar.y"
    {
		(yyval.param).self = AddPayload((yyvsp[(2) - (3)].s), (yyvsp[(3) - (3)].s), NULL); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 55:
#line 417 "filter/grammar.y"
    {
		(yyval.param).self = AddPayload((yyvsp[(2) - (4)].s), (yyvsp[(3) - (4)].s), (yyvsp[(4) - (4)].s)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 56:
#line 421 "filter/grammar.y"
    {
		(yyval.param).self = AddGeo((yyvsp[(1) - (3)].param).direction, (yyvsp[(3) - (3)].s)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 57:
#line 425 "filter/grammar.y"
    {
		(yyval.param).self = AddObservation((yyvsp[(2) - (5)].s), (yyvsp[(3) - (5)].s), (yyvsp[(4) - (5)].param).comp, (yyvsp[(5) - (5)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 58:
#line 429 "filter/grammar.y"
    {
		(yyval.param).self = AddVRF((yyvsp[(1) - (4)].param).direction, (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 59:
#line 433 "filter/grammar.y"
    {
		(yyval.param).self = AddPFString((yyvsp[(2) - (3)].s), (yyvsp[(3) - (3)].s)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 60:
#line 437 "filter/grammar.y"
    {
		(yyval.param).self = AddPFNumber((yyvsp[(2) - (4)].s), (yyvsp[(3) - (4)].param).comp, (yyvsp[(4) - (4)].value)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 61:
#line 441 "filter/grammar.y"
    {
		switch ((yyvsp[(3) - (3)].param).direction) {
			case DIR_IN:
				(yyval.param).self = AddPFString((yyvsp[(2) - (3)].s), "in");
				break;
			case DIR_OUT:
				(yyval.param).self = AddPFString((yyvsp[(2) - (3)].s), "out");
				break;
			case DIR_UNSPEC_NAT:
				(yyval.param).self = AddPFString((yyvsp[(2) - (3)].s), "nat");
				break;
			default:
				(yyval.param).self = -1;
				yyerror("Unknown direction specifier");
		}
		if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 62:
#line 459 "filter/grammar.y"
    { 	
		(yyval.param).self = AddIPlist((yyvsp[(1) - (6)].param).direction, (yyvsp[(5) - (6)].list)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 63:
#line 463 "filter/grammar.y"
    {
		(yyval.param).self = AddPortList((yyvsp[(1) - (6)].param).direction, (yyvsp[(5) - (6)].list)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 64:
#line 467 "filter/grammar.y"
    {
		(yyval.param).self = AddASList((yyvsp[(1) - (6)].param).direction, (yyvsp[(5) - (6)].list)); if ( (yyval.param).self < 0 ) YYABORT;
	}
    break;

  case 65:
#line 473 "filter/grammar.y"
    { 
		(yyval.list) = NewIplist((yyvsp[(1) - (1)].s), -1); if ( (yyval.list) == NULL ) YYABORT;
	}
    break;

  case 66:
#line 477 "filter/grammar.y"
    { 
		(yyval.list) = NewIplist((yyvsp[(1) - (3)].s), (yyvsp[(3) - (3)].value)); if ( (yyval.list) == NULL ) YYABORT;
	}
    break;

  case 67:
#line 481 "filter/grammar.y"
    { 
		if (InsertIPlist((yyvsp[(1) - (2)].list), (yyvsp[(2) - (2)].s), -1) == 0 ) YYABORT;
	}
    break;

  case 68:
#line 485 "filter/grammar.y"
    { 
		if (InsertIPlist((yyvsp[(1) - (3)].list), (yyvsp[(3) - (3)].s), -1) == 0 ) YYABORT;
	}
    break;

  case 69:
#line 489 "filter/grammar.y"
    { 
		if (InsertIPlist((yyvsp[(1) - (4)].list), (yyvsp[(2) - (4)].s), (yyvsp[(4) - (4)].value)) == 0 ) YYABORT;
	}
    break;

  case 70:
#line 494 "filter/grammar.y"
    { 
		(yyval.list) = NewU64list((yyvsp[(1) - (1)].value)); if ( (yyval.list) == NULL ) YYABORT;
	}
    break;

  case 71:
#line 498 "filter/grammar.y"
    { 
		if (InsertU64list((yyvsp[(1) - (2)].list), (yyvsp[(2) - (2)].value)) == 0 ) YYABORT;
	}
    break;

  case 72:
#line 502 "filter/grammar.y"
    { 
		if (InsertU64list((yyvsp[(1) - (3)].list), (yyvsp[(3) - (3)].value)) == 0 ) YYABORT;
	}
    break;

  case 73:
#line 508 "filter/grammar.y"
    { (yyval.param).comp = CMP_EQ; }
    break;

  case 74:
#line 509 "filter/grammar.y"
    { (yyval.param).comp = CMP_EQ; }
    break;

  case 75:
#line 510 "filter/grammar.y"
    { (yyval.param).comp = CMP_LT; }
    break;

  case 76:
#line 511 "filter/grammar.y"
    { (yyval.param).comp = CMP_GT; }
    break;

  case 77:
#line 512 "filter/grammar.y"
    { (yyval.param).comp = CMP_LE; }
    break;

  case 78:
#line 513 "filter/grammar.y"
    { (yyval.param).comp = CMP_GE; }
    break;

  case 79:
#line 517 "filter/grammar.y"
    { (yyval.param).direction = DIR_UNSPEC;   }
    break;

  case 80:
#line 518 "filter/grammar.y"
    { (yyval.param).direction = DIR_SRC;      }
    break;

  case 81:
#line 519 "filter/grammar.y"
    { (yyval.param).direction = DIR_DST;      }
    break;

  case 82:
#line 520 "filter/grammar.y"
    { (yyval.param).direction = DIR_SRC_NAT;	}
    break;

  case 83:
#line 521 "filter/grammar.y"
    { (yyval.param).direction = DIR_DST_NAT;	}
    break;

  case 84:
#line 522 "filter/grammar.y"
    { (yyval.param).direction = DIR_SRC_TUN;  }
    break;

  case 85:
#line 523 "filter/grammar.y"
    { (yyval.param).direction = DIR_DST_TUN;  }
    break;

  case 86:
#line 524 "filter/grammar.y"
    { (yyval.param).direction = DIR_UNSPEC_NAT; }
    break;

  case 87:
#line 525 "filter/grammar.y"
    { (yyval.param).direction = DIR_UNSPEC_TUN; }
    break;

  case 88:
#line 526 "filter/grammar.y"
    { (yyval.param).direction = DIR_IN;       }
    break;

  case 89:
#line 527 "filter/grammar.y"
    { (yyval.param).direction = DIR_OUT;      }
    break;

  case 90:
#line 528 "filter/grammar.y"
    { (yyval.param).direction = DIR_IN_SRC;   }
    break;

  case 91:
#line 529 "filter/grammar.y"
    { (yyval.param).direction = DIR_IN_DST;   }
    break;

  case 92:
#line 530 "filter/grammar.y"
    { (yyval.param).direction = DIR_OUT_SRC;	}
    break;

  case 93:
#line 531 "filter/grammar.y"
    { (yyval.param).direction = DIR_OUT_DST;  }
    break;

  case 94:
#line 532 "filter/grammar.y"
    { (yyval.param).direction = DIR_INGRESS;  }
    break;

  case 95:
#line 533 "filter/grammar.y"
    { (yyval.param).direction = DIR_EGRESS;   }
    break;

  case 96:
#line 534 "filter/grammar.y"
    { (yyval.param).direction = DIR_PREV;     }
    break;

  case 97:
#line 535 "filter/grammar.y"
    { (yyval.param).direction = DIR_NEXT;     }
    break;

  case 98:
#line 536 "filter/grammar.y"
    { (yyval.param).direction = BGP_NEXT;	}
    break;

  case 99:
#line 537 "filter/grammar.y"
    { (yyval.param).direction = SRC_ROUTER;   }
    break;

  case 100:
#line 538 "filter/grammar.y"
    { (yyval.param).direction = SRC_ROUTER;   }
    break;

  case 101:
#line 541 "filter/grammar.y"
    { (yyval.value) = (yyvsp[(1) - (1)].param).self; }
    break;

  case 102:
#line 542 "filter/grammar.y"
    { (yyval.value) = Connect_OR((yyvsp[(1) - (3)].value), (yyvsp[(3) - (3)].value));   }
    break;

  case 103:
#line 543 "filter/grammar.y"
    { (yyval.value) = Connect_AND((yyvsp[(1) - (3)].value), (yyvsp[(3) - (3)].value));  }
    break;

  case 104:
#line 544 "filter/grammar.y"
    { (yyval.value) = Invert((yyvsp[(2) - (2)].value)); }
    break;

  case 105:
#line 545 "filter/grammar.y"
    { (yyval.value) = (yyvsp[(2) - (3)].value); }
    break;


/* Line 1267 of yacc.c.  */
#line 2476 "filter/grammar.c"
      default: break;
    }
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
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yymsg);
	  }
	else
	  {
	    yyerror (YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
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

  /* Else will try to reuse look-ahead token after shifting the error
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
      if (yyn != YYPACT_NINF)
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

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;


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

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval);
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


#line 548 "filter/grammar.y"


static void yyerror(char *msg, ...) {
	char msgStr[128];

	va_list var_args;
  va_start(var_args, msg);
	vsnprintf(msgStr, 127, msg, var_args);
  va_end(var_args);
	msgStr[127] = '\0';

	if ( FilterFilename ) {
		printf("File '%s' line %d: %s at '%s'\n", FilterFilename, lineno, msgStr, yytext);
	} else {
		printf("Line %d: %s at '%s'\n", lineno, msgStr, yytext);
	}
} /* End of yyerror */

static uint32_t NewIPElement(ipStack_t *ipStack, int direction, int comp, data_t *data) {

	int block = -1;

	if ( ipStack->af == PF_INET ) {
		// handle IPv4 addr element
		switch ( direction ) {
			case DIR_SRC:
				block = NewElement(EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_DST:
				block = NewElement(EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_SRC_NAT:
				block = NewElement(EXnatXlateIPv4ID, OFFxlateSrc4Addr, SIZExlateSrc4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_DST_NAT:
				block = NewElement(EXnatXlateIPv4ID, OFFxlateDst4Addr, SIZExlateDst4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_SRC_TUN:
				block = NewElement(EXtunIPv4ID, OFFtunSrc4Addr, SIZEtunSrc4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_DST_TUN:
				block = NewElement(EXtunIPv4ID, OFFtunDst4Addr, SIZEtunDst4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_NEXT:
				block = NewElement(EXipNextHopV4ID, OFFNextHopV4IP, SIZENextHopV4IP, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case BGP_NEXT:
				block = NewElement(EXbgpNextHopV4ID, OFFbgp4NextIP, SIZEbgp4NextIP, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case SRC_ROUTER:
				block = NewElement(EXipReceivedV4ID, OFFReceived4IP, SIZEReceived4IP, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
		} // End of switch

	} else {
		// handle IPv6 addr element
		int v6_1, v6_2 = 0;
		switch ( direction ) {
			case DIR_SRC:
				v6_1 = NewElement(EXipv6FlowID, OFFsrc6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXipv6FlowID, OFFsrc6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_DST:
				v6_1 = NewElement(EXipv6FlowID, OFFdst6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXipv6FlowID, OFFdst6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_SRC_NAT:
				v6_1 = NewElement(EXnatXlateIPv6ID, OFFxlateSrc6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXnatXlateIPv6ID, OFFxlateSrc6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_DST_NAT:
				v6_1 = NewElement(EXnatXlateIPv6ID, OFFxlateDst6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXnatXlateIPv6ID, OFFxlateDst6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_SRC_TUN:
				v6_1 = NewElement(EXtunIPv6ID, OFFtunSrc6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXtunIPv6ID, OFFtunSrc6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_DST_TUN:
				v6_1 = NewElement(EXtunIPv6ID, OFFtunDst6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXtunIPv6ID, OFFtunDst6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_NEXT:
				v6_1 = NewElement(EXipNextHopV6ID, OFFNextHopV6IP, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXipNextHopV6ID, OFFNextHopV6IP + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case BGP_NEXT:
				v6_1 = NewElement(EXbgpNextHopV6ID, OFFbgp6NextIP, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXbgpNextHopV6ID, OFFbgp6NextIP + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case SRC_ROUTER:
				v6_1 = NewElement(EXipReceivedV6ID, OFFReceived6IP, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXipReceivedV6ID, OFFReceived6IP + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
		} // End of switch

		// IPv6
		if ( v6_1 && v6_2 )
			block = Connect_AND(v6_1, v6_2);

	}

	return block;
} // NewIPElement

static uint32_t ChainHosts(ipStack_t *ipStack, int numIP, int direction) {

	data_t data[2] = { NULLPtr, NULLPtr };

	uint32_t final = 0;
	int i = 0;
	do {
		// chain multiple IPs
		int block = NewIPElement(&ipStack[i], direction, CMP_EQ, data);
		final = final == 0 ? block : Connect_OR(final, block);

	} while (++i < numIP);
	
	return final;
} // End of ChainHosts

static int AddIdent(char *ident) {
	char *c;

	// ident[a-zA-Z0-9_\-]+ { 
	size_t len = strlen(ident);
	if ( len == 0 || len > 255 ) {
		yyerror("Invalid ident string: %s", ident);
		return -1;
	}
	
	c = &ident[0];
	while ( *c ) {
		if ( *c != '_' && *c != '-' && !isalnum(*c) ) {
			yyerror("Invalid char in ident string: %s: %c", ident, *c);
			return 0;
		}
		c++;
	}
	
	data_t data = {.dataPtr = strdup(ident)};
	return NewElement(EXnull, 0, 0, 0, CMP_IDENT, FUNC_NONE, data); 

} // End of AddIdent

static int AddProto(direction_t direction, char *protoStr, uint64_t protoNum) {

	if ( protoNum > 255 ) {
		yyerror("Protocol %d out of range", protoNum);
		return -1;
	}

	if ( protoStr != NULL ) {
		protoNum = ProtoNum(protoStr);
  	if ( protoNum == -1 ) {
	  	yyerror("Unknown protocol: %s", protoStr);
			Protoinfo(protoStr);
			return -1;
  	}
	}

	if ( direction == DIR_UNSPEC ) {
		return NewElement(EXgenericFlowID, OFFproto, SIZEproto, protoNum, CMP_EQ, FUNC_NONE, NULLPtr); 
	} else if ( direction == DIR_UNSPEC_TUN ) {
		return Connect_OR(
			NewElement(EXtunIPv4ID, OFFtunProtoV4, SIZEtunProtoV4, protoNum, CMP_EQ, FUNC_NONE, NULLPtr),
			NewElement(EXtunIPv6ID, OFFtunProtoV6, SIZEtunProtoV6, protoNum, CMP_EQ, FUNC_NONE, NULLPtr)
		);
	} else {
	  	yyerror("Unknown protocol specifier");
			return -1;
	}
} // End of AddProtoString

static int AddEngineNum(char *type, uint16_t comp, uint64_t num) {
	if ( num > 255 ) {
		yyerror("Engine argument %d of range 0..255", num);
		return -1;
  }

	int ret = -1;
	if ( strcasecmp(type, "type") == 0 ) {
		ret = NewElement(EXnull, OFFengineType, SIZEengineType, num, comp, FUNC_NONE, NULLPtr);
	} else if ( strcasecmp(type, "id") == 0 ) {
		ret = NewElement(EXnull, OFFengineID, SIZEengineID, num, comp, FUNC_NONE, NULLPtr);
	}

	return ret;
} // End of AddEngineNum

static int AddExporterNum(char *type, uint16_t comp, uint64_t num) {
	if ( num > 65535 ) {
	  yyerror("Exporter argument %d of range 0..65535", num);
		return -1;
	}

	int ret = -1;
  if ((strcasecmp(type, "id") == 0 ) || (strcasecmp(type, "sysid") == 0)) {
		ret = NewElement(EXnull, OFFexporterID, SIZEexporterID, num, comp, FUNC_NONE, NULLPtr);
	} else {
	  yyerror("Unknown exporter argument: %s", type);
	}

	return ret;
} // End of AddExporterNum

static int AddPortNumber(direction_t direction, uint16_t comp, uint64_t port) {
	if ( port > 65535 ) {
		  yyerror("Port number: %d out of range", port);
			return -1;
	}

	int ret = -1;
  switch ( direction ) {
	  case DIR_SRC:
		  ret = NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, port, comp, FUNC_NONE, NULLPtr);
		  break;
	  case DIR_DST:
		  ret = NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, port, comp, FUNC_NONE, NULLPtr);
		  break;
	  case DIR_SRC_NAT:
		  ret = NewElement(EXnatXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, port, comp, FUNC_NONE, NULLPtr);
		  break;
	  case DIR_DST_NAT:
		  ret = NewElement(EXnatXlatePortID, OFFxlateDstPort, SIZExlateDstPort, port, comp, FUNC_NONE, NULLPtr);
		  break;
	  case DIR_UNSPEC:
		  ret = Connect_OR(
			  NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, port, comp, FUNC_NONE, NULLPtr),
			  NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, port, comp, FUNC_NONE, NULLPtr)
		  );
		  break;
	  case DIR_UNSPEC_NAT:
		  ret = Connect_OR(
		  	NewElement(EXnatXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, port, comp, FUNC_NONE, NULLPtr),
		  	NewElement(EXnatXlatePortID, OFFxlateDstPort, SIZExlateDstPort, port, comp, FUNC_NONE, NULLPtr)
		  );
		  break;
	  default:
		  yyerror("Unknown direction");
  } // End switch

	return ret;
} // End of AddPortNumber

static int AddICMP(char *type, uint16_t comp, uint64_t number) {
	if ( number > 255 ) {
		  yyerror("ICMP argument of range 0..255");
			return -1;
  }

	int ret = -1;
	// imply ICMP-TYPE with a proto ICMP block
	int protoICMP = Connect_OR (
			  NewElement(EXgenericFlowID, OFFproto, SIZEproto, IPPROTO_ICMP, CMP_EQ, FUNC_NONE, NULLPtr), 
			  NewElement(EXgenericFlowID, OFFproto, SIZEproto, IPPROTO_ICMPV6, CMP_EQ, FUNC_NONE, NULLPtr)
		  );
	if ( strcasecmp(type, "type") == 0 ) {
		ret = Connect_AND(
			protoICMP,
		  NewElement(EXgenericFlowID, OFFicmpType, SIZEicmpType, number, comp, FUNC_NONE, NULLPtr)
	  );
	} else if ( strcasecmp(type, "code") == 0 ) {
		ret = Connect_AND(
			protoICMP,
			NewElement(EXgenericFlowID, OFFicmpCode, SIZEicmpCode, number, comp, FUNC_NONE, NULLPtr)
	  );
	} 

	return ret;
} // End of AddICMP

static int AddFlagsNumber(direction_t direction, uint16_t comp, uint64_t flags) {
	if ( flags > 255 ) {
		  yyerror("flags number > 255");
			return -1;
	}

	// direction ignored

	return Connect_AND(
	  // imply flags with proto TCP
	  NewElement(EXgenericFlowID, OFFproto, SIZEproto, IPPROTO_TCP, CMP_EQ, FUNC_NONE, NULLPtr), 
	  NewElement(EXgenericFlowID, OFFtcpFlags, SIZEtcpFlags, flags, comp, FUNC_NONE, NULLPtr)
  );
} // End of AddFlagsNumber

static int AddFlagsString(direction_t direction, char *flags) {
	size_t len = strlen(flags);
  if ( len > 10 ) {
	  yyerror("Flags string error");
		return -1;
  }

	int strict = 0;
	if ( flags[0] == '=') {
	  strict = 1;
	  len--;
  }

  int cnt     = 0;
  uint64_t fl = 0;
  if ( strchr(flags, 'F') ) { fl |=  1; cnt++; }
  if ( strchr(flags, 'S') ) { fl |=  2; cnt++; }
  if ( strchr(flags, 'R') ) { fl |=  4; cnt++; }
  if ( strchr(flags, 'P') ) { fl |=  8; cnt++; }
  if ( strchr(flags, 'A') ) { fl |=  16; cnt++; }
  if ( strchr(flags, 'U') ) { fl |=  32; cnt++; }
  if ( strchr(flags, 'E') ) { fl |=  64; cnt++; }
  if ( strchr(flags, 'C') ) { fl |= 128; cnt++; }
  if ( strchr(flags, 'X') ) { fl =  63; cnt++; }

  if ( cnt != len ) {
	  yyerror("Unknown flags");
		return -1;
  }

  if (strict) {
		return AddFlagsNumber(direction, CMP_EQ, fl);
  } else {
		return AddFlagsNumber(direction, CMP_FLAGS, fl);
  }

	// unreached
} // End of AddFlagsString

static int AddTosNumber(direction_t direction, uint16_t comp, uint64_t tos) {
	if ( tos > 255 ) {
		yyerror("Tos number out of range");
		return -1;
  }

	int ret = -1;
  switch (direction) {
	  case DIR_UNSPEC:
	  case DIR_SRC: 
		  ret = NewElement(EXgenericFlowID, OFFsrcTos, SIZEsrcTos, tos, comp, FUNC_NONE, NULLPtr);
		  break;
	  case DIR_DST: 
		  ret = NewElement(EXflowMiscID, OFFdstTos, SIZEdstTos, tos, comp, FUNC_NONE, NULLPtr);
		  break;
	  default:
		  yyerror("syntax error");
  } // End of switch

	return ret;
} // End of AddTosNumber

static int AddPackets(direction_t direction, uint16_t comp, uint64_t packets) {

	int ret = -1;
	switch ( direction ) {
		case DIR_UNSPEC:
	  case DIR_IN: 
		  ret = NewElement(EXgenericFlowID, OFFinPackets, SIZEinPackets, packets, comp, FUNC_NONE, NULLPtr); 
		  break;
	  case DIR_OUT: 
		  ret = NewElement(EXgenericFlowID, OFFoutPackets, SIZEoutPackets, packets, comp, FUNC_NONE, NULLPtr); 
		break;
	  default:
		  yyerror("Invalid direction for packets");
	} // End of switch
	return ret;
} // End of AddPackets

static int AddBytes(direction_t direction, uint16_t comp, uint64_t bytes) {
	int ret = -1;
	switch ( direction ) {
	  case DIR_UNSPEC:
	  case DIR_IN: 
		  ret = NewElement(EXgenericFlowID, OFFinBytes, SIZEinBytes, bytes, comp, FUNC_NONE, NULLPtr); 
		  break;
	  case DIR_OUT: 
		  ret = NewElement(EXgenericFlowID, OFFoutBytes, SIZEoutBytes, bytes, comp, FUNC_NONE, NULLPtr); 
		  break;
	  default:
		  yyerror("Invalid direction for bytes");
	 } // End of switch
	 return ret;
} // End of AddBytes

static int AddFwdStatNum(uint16_t comp, uint64_t num) {
	if ( num > 255 ) {
	  yyerror("Forwarding status: %d our of range", num);
		return -1;
	}

	return NewElement(EXgenericFlowID, OFFfwdStatus, SIZEfwdStatus, num, comp, FUNC_NONE, NULLPtr);
} // End of AddFwdStatNum

static int AddFwdStatString(char *string) {
	int	fwdStatus = fwdStatusNum(string);
	if ( fwdStatus < 0 ) {
	  fwdStatusInfo();
	  yyerror("Unkown forwarding status: %s", string);
		return -1;
	}

	return NewElement(EXgenericFlowID, OFFfwdStatus, SIZEfwdStatus, fwdStatus, CMP_EQ, FUNC_NONE, NULLPtr);
} // End of AddFwdStatString

static int AddMPLS(char *type, uint16_t comp, uint64_t value) {
	if ( strncasecmp(type, "label", 5) == 0 ) {
		char *s = type + 5;
		if ( *s == '\0' ) {
			yyerror("Missing mpls stack number for label");
			return -1;
		}
		int lnum = (int)strtol(s, (char **)NULL, 10);
		data_t labelIndex = { .dataVal = lnum};
		return NewElement(EXmplsLabelID, 0, 0, value, comp, FUNC_MPLS_LABEL, labelIndex);
	} else if ( strcasecmp(type, "any") == 0 ) {
		data_t labelValue = { .dataVal = value};
		return NewElement(EXmplsLabelID, 0, 0, value, comp, FUNC_MPLS_ANY, labelValue);
	} else if ( strcasecmp(type, "eos") == 0 ) {
		// match End of Stack label 
		return NewElement(EXmplsLabelID, 0, 0, value, comp, FUNC_MPLS_EOS, NULLPtr);
	} else if ( strncasecmp(type, "exp", 3) == 0 ) {
		char *s = type + 3;
		if ( *s == '\0' ) {
			yyerror("Missing mpls stack number for exp value");
			return -1;
		}
		int lnum = (int)strtol(s, (char **)NULL, 10);
		data_t data = {.dataVal = lnum};
		return NewElement(EXmplsLabelID, 0, 0, value, comp, FUNC_MPLS_EXP, data);
	} else {
			yyerror("Unknown mpls argument: %s", type);
			return -1;
	}

	// unreached
	return -1;
} // End of AddMPLS

static int AddEthertype(uint64_t etherType) {
	return NewElement(EXlayer2ID, OFFetherType, SIZEetherType, etherType, CMP_EQ, FUNC_NONE, NULLPtr);
} // End of AddMAC

static int AddMAC(direction_t direction, char *macString) {

	uint64_t macVal = Str2Mac(macString);
	if ( macVal == 0 ) return -1;

	switch (direction) {
		case DIR_IN_SRC:
			return NewElement(EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_IN_DST:
			return NewElement(EXmacAddrID, OFFinDstMac, SIZEinDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_OUT_SRC:
			return NewElement(EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_OUT_DST:
			return NewElement(EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_SRC:
			return Connect_OR (
				NewElement(EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_DST:
			return Connect_OR (
				NewElement(EXmacAddrID, OFFinDstMac, SIZEinDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_IN:
			return Connect_OR (
				NewElement(EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXmacAddrID, OFFinDstMac, SIZEinDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_OUT:
			return Connect_OR (
				NewElement(EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_UNSPEC: {
				int in = Connect_OR (
					NewElement(EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
					NewElement(EXmacAddrID, OFFinDstMac, SIZEinDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
				);
				int out = Connect_OR (
					NewElement(EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
					NewElement(EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
				);
				return Connect_OR(in, out);
			} break;
		default:
			yyerror("Unknown mac argument");
			return -1;
	}

	// unreached
	return -1;
} // End of AddMAC

static int AddLatency(char *type, uint16_t comp, uint64_t number) {

	int ret = -1;
	if ( strcasecmp(type, "client") == 0 ) {
			ret =  NewElement(EXlatencyID, OFFusecClientNwDelay, SIZEusecClientNwDelay, number, comp, FUNC_NONE, NULLPtr);
	} if ( strcasecmp(type, "server") == 0 ) {
			ret =  NewElement(EXlatencyID, OFFusecServerNwDelay, SIZEusecServerNwDelay, number, comp, FUNC_NONE, NULLPtr);
	} if ( strcasecmp(type, "app") == 0 ) { 
			ret =  NewElement(EXlatencyID, OFFusecApplLatency, SIZEusecApplLatency, number, comp, FUNC_NONE, NULLPtr);
	}	

	return ret;
} // End of AddLatency

static int AddASAString(char *event, char *asaStr) {

	if (strcasecmp(event, "event") == 0) {
		int eventNum = fwEventID(asaStr);
		if ( eventNum < 0 ) {
			yyerror("Invalid ASA event type: %s", asaStr);
			return -1;
		}
		return NewElement(EXnselCommonID, OFFfwEvent, SIZEfwEvent, eventNum, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(event, "denied") == 0) {
		int eventNum = fwXEventID(asaStr);
		if ( eventNum < 0 ) {
			yyerror("Invalid ASA Xevent type: %s", asaStr);
			return -1;
		}
		return NewElement(EXnselCommonID, OFFfwXevent, SIZEfwXevent, eventNum, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(event, "user") == 0) {
		if ( strlen(asaStr) > 65 ) {
			yyerror("Length of ASA user name: %s > 65 chars", asaStr);
			return -1;
		}
		data_t data = {.dataPtr = strdup(asaStr)};
		return NewElement(EXnselUserID, OFFusername, 0, 0, CMP_STRING, FUNC_NONE, data);
	}

	yyerror("Invalid ASA type: %s", event);
	return -1;

} // End of AddASAString

static int AddASA(char *event, uint16_t comp, uint64_t number) {

	if ( strcasecmp(event, "event") == 0 ) {
		if ( number > 5 ) {
			yyerror("Invalid event number %llu. Expected 0..5", number);
			return -1;
		}
		return NewElement(EXnselCommonID, OFFfwEvent, SIZEfwEvent, number, comp, FUNC_NONE, NULLPtr);
	} else if ( strcasecmp(event, "xevent") == 0 ) {
		return NewElement(EXnselCommonID, OFFfwXevent, SIZEfwXevent, number, comp, FUNC_NONE, NULLPtr);
	}

	yyerror("Invalid ASA type: %s", event);
	return -1;

} // End of AddASA

static int AddACL(direction_t direction, uint16_t comp, uint64_t number) {

	uint32_t offset = 0;
	switch (direction) {
		case DIR_INGRESS:
			offset = OFFingressAcl;
			break;
		case DIR_EGRESS:
			offset = OFFegressAcl;
			break;
		default:
			yyerror("Invalid ACL direction");
			return -1;
	}
	
	uint32_t acl[3];
	acl[0] = NewElement(EXnselAclID, offset, sizeof(uint32_t), number, comp, FUNC_NONE, NULLPtr);
	acl[1] = NewElement(EXnselAclID, offset + sizeof(uint32_t), sizeof(uint32_t), number, comp, FUNC_NONE, NULLPtr);
	acl[2] = NewElement(EXnselAclID, offset + 2*sizeof(uint32_t), sizeof(uint32_t), number, comp, FUNC_NONE, NULLPtr);
	return Connect_OR (
		Connect_OR(acl[0], acl[1]), acl[2]
	);
	return -1;

} // End of AddASA

static int AddASApblock(direction_t direction, char *arg) {

	if (strcasecmp(arg, "pblock") != 0) {
			yyerror("Invalid port block: %s", arg);
			return -1;
	}

	int ret = -1;
	switch (direction) {
		case DIR_SRC:
		  ret = NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 1, CMP_EQ, FUNC_PBLOCK, NULLPtr);
		  break;
	  case DIR_DST:
		  ret = NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, 1, CMP_EQ, FUNC_PBLOCK, NULLPtr);
		  break;
	  case DIR_UNSPEC:
		  ret = Connect_OR(
			  NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 1, CMP_EQ, FUNC_PBLOCK, NULLPtr),
			  NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, 1, CMP_EQ, FUNC_PBLOCK, NULLPtr)
		  );
		  break;
		default:
			yyerror("Invalid port direction");
	}

	return ret;
} // End of AddASApblock

static int AddNATString(char *event, char *natStr) {

	if (strcasecmp(event, "event") == 0) {
		int eventNum = natEventNum(natStr);
		if ( eventNum < 0 ) {
			yyerror("Invalid NAT event type: %s", natStr);
			natEventInfo();
			return -1;
		}
		return NewElement(EXnelCommonID, OFFnatEvent, SIZEnatEvent, eventNum, CMP_EQ, FUNC_NONE, NULLPtr);
	} 

	yyerror("Invalid NAT type: %s", event);
	return -1;

} // End of AddNATString

static int AddNAT(char *event, uint16_t comp, uint64_t number) {

	if (strcasecmp(event, "event") == 0) {
		if ( number > MAX_NAT_EVENTS ) {
			yyerror("NAT event: %llu out of range\n", number);
			return -1;
		}
		return NewElement(EXnelCommonID, OFFnatEvent, SIZEnatEvent, number, comp, FUNC_NONE, NULLPtr);
	} 

	return -1;
} // End of AddNAT

static int AddNatPortBlocks(char *type, char *subtype, uint16_t comp, uint64_t number) {

	uint32_t offset = 0;
	if (strcasecmp(type, "pblock") == 0) {
		if (strcasecmp(subtype, "start") == 0) {
			offset = OFFnelblockStart;
		} else if (strcasecmp(subtype, "end") == 0) {
			offset = OFFnelblockEnd;
		} else if (strcasecmp(subtype, "step") == 0) {
			offset = OFFnelblockStep;
		} else if (strcasecmp(subtype, "size") == 0) {
			offset = OFFnelblockSize;
		} else {
			yyerror("Unknown port block argument: %s\n", subtype);
			return -1;
		}
	} else {
			yyerror("Unknown NAT argument: %s\n", type);
			return -1;
	}

	return NewElement(EXnatPortBlockID, offset, SIZEnelblockStart, number, comp, FUNC_NONE, NULLPtr);
	return -1;
} // End of AddNatPortBlocks

static int AddPayloadSSL(char *type, char *arg, char *opt) {
	if (strcasecmp(arg, "defined") == 0) {
		return NewElement(SSLindex, 0, 0, 0, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(arg, "version") == 0) {
		if ( opt == NULL ){
			yyerror("String %s is not a valid SSL/TLS version", arg);
			return -1;
		}
		unsigned int major, minor;
		if (sscanf(opt, "%1u.%1u", &major, &minor) != 2 || major > 3 || minor > 3 ) {
			yyerror("String %s is not a valid SSL/TLS version", opt);
			return -1;
		}
		// if old SSL 1.0, 2.0 or 3.0
		if (major > 1 && minor > 0){
			yyerror("String %s is not a valid SSL/TLS version", opt);
			return -1;
		}
		uint16_t version = 0;
		if ( strcasecmp(type, "tls") == 0 ) {
			if (major > 1){
				yyerror("String %s is not a valid TLS version", opt);
				return -1;
			}
			// TLS
			version = (0x03 << 8) | (minor + 1);
		} else {
			if (minor > 0){
				yyerror("String %s is not a valid SSL version", opt);
				return -1;
			}
			// SSL
			version = major << 8;
		}
		return NewElement(SSLindex, OFFsslVersion, SIZEsslVersion, version, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(arg, "sni") == 0) {
		if ( opt == NULL || strlen(opt) > 64 ) {
			yyerror("Invalid string %s for SSL/TLS sni name", opt != NULL ? opt : "");
			return -1;
		}
		data_t data = {.dataPtr=strdup(opt)};
		return NewElement(SSLindex, OFFsslSNI, SIZEsslSNI, 0, CMP_SUBSTRING, FUNC_NONE, data);
	}
	yyerror("String %s is not a valid SSL/TLS filter", arg);
	return -1;
} // End of AddPayloadSSL

static int AddPayloadJA3(char *type, char *arg, char *opt) {
	if (strcasecmp(arg, "defined") == 0) {
		return NewElement(JA3index, OFFja3String, SIZEja3String, 0, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (IsMD5(arg) == 0) {
		yyerror("String %s is not a valid ja3 string", arg);
		return -1;
	}
	data_t data = {.dataPtr=strdup(arg)};
	return NewElement(JA3index, OFFja3String, SIZEja3String, 0, CMP_STRING, FUNC_NONE, data);
} // End of AddPayloadJA3

static int AddPayloadJA4(char *type, char *arg, char *opt) {
	if (strcasecmp(arg, "defined") == 0) {
		return NewElement(JA4index, OFFja4String, SIZEja3String, 0, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if ( ja4Check(arg) == 0 ){
		yyerror("String %s is not a valid ja4 string", arg);
		return -1;
	}
	data_t data = {.dataPtr=strdup(arg)};
	return NewElement(JA4index, OFFja4String, SIZEja4String, 0, CMP_STRING, FUNC_NONE, data);
} // End of AddPayloadJA4

static int AddPayload(char *type, char *arg, char *opt) {

	if (strcasecmp(type, "content") == 0) {
		data_t data = {.dataPtr = arg};
		return NewElement(EXinPayloadID, 0, 0, 0, CMP_PAYLOAD, FUNC_NONE, data);
	} else if (strcasecmp(type, "regex") == 0) {
		int err[2];
		char *regexArg = opt ? opt : "";
		srx_Context *program = srx_CreateExt(arg, strlen(arg), regexArg, err, NULL, NULL);
		if ( !program ) {
			yyerror("failed to compile regex: %s", arg);
			return -1;
		}
		data_t data = {.dataPtr = program};
		return NewElement(EXinPayloadID, 0, 0, 0, CMP_REGEX, FUNC_NONE, data);
	} else if (strcasecmp(type, "ssl") == 0 || strcasecmp(type, "tls") == 0) {
		return AddPayloadSSL(type, arg, opt);
	} else if (strcasecmp(type, "ja3") == 0) {
		return AddPayloadJA3(type, arg, opt);
	} else if (strcasecmp(type, "ja4") == 0) {
		return AddPayloadJA4(type, arg, opt);
	} else if (strcasecmp(type, "ja4s") == 0) {
#ifdef BUILDJA4
		if ( ja4sCheck(arg) == 0 ){
			yyerror("String %s is not a valid ja4s string", arg);
			return -1;
		}
		data_t data = {.dataPtr=strdup(arg)};
		return NewElement(JA4index, OFFja4String, SIZEja4sString, 0, CMP_STRING, FUNC_NONE, data);
#else
		yyerror("ja4s code not enabled", arg);
		return -1;
#endif
	} else {
		yyerror("Unknown PAYLOAD argument: %s\n", type);
		return -1;
	}

	return -1;
} // End of AddPayload

static int AddGeo(direction_t direction, char *geo) {

	if ( strlen(geo) != 2 ) {
			yyerror("Unknown Geo country: %s. Need a two letter country code.", geo);
			return -1;
	}

	data_t data = {.dataVal = direction};
	int ret = -1;
	uint64_t geoVal = toupper(geo[0]) + (toupper(geo[1]) << 8);
	switch (direction) {
		case DIR_SRC:
			ret = NewElement(EXlocal, OFFgeoSrcIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_DST:
			ret = NewElement(EXlocal, OFFgeoDstIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_SRC_NAT:
			ret = NewElement(EXlocal, OFFgeoSrcNatIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_DST_NAT:
			ret = NewElement(EXlocal, OFFgeoDstNatIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_SRC_TUN:
			ret = NewElement(EXlocal, OFFgeoSrcTunIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_DST_TUN:
			ret = NewElement(EXlocal, OFFgeoDstTunIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_UNSPEC: {
			data_t srcData = {.dataVal = DIR_SRC};
			data_t dstData = {.dataVal = DIR_DST};
			ret = Connect_OR(
				NewElement(EXlocal, OFFgeoSrcIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, srcData),
				NewElement(EXlocal, OFFgeoDstIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, dstData)
			);
			} break;
		case DIR_UNSPEC_NAT: {
			data_t srcData = {.dataVal = DIR_SRC_NAT};
			data_t dstData = {.dataVal = DIR_DST_NAT};
			ret = Connect_OR(
				NewElement(EXlocal, OFFgeoSrcNatIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, srcData),
				NewElement(EXlocal, OFFgeoDstNatIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, dstData)
			);
			} break;
		case DIR_UNSPEC_TUN: {
			data_t srcData = {.dataVal = DIR_SRC_TUN};
			data_t dstData = {.dataVal = DIR_DST_TUN};
			ret = Connect_OR(
				NewElement(EXlocal, OFFgeoSrcTunIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, srcData),
				NewElement(EXlocal, OFFgeoDstTunIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, dstData)
			);
			} break;
		default:
			yyerror("Unknown Geo specifier");
	}

	return ret;
} // End of AddGeo

static int AddObservation(char *type, char *subType, uint16_t comp, uint64_t number) {

	if (strcasecmp(subType, "id") != 0) {
			yyerror("Unknown observation specifier: %s", subType);
			return -1;
	}
	int ret = -1;
	if (strcasecmp(type, "domain") == 0) {
		ret =  NewElement(EXobservationID, OFFdomainID, SIZEdomainID, number, comp, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(type, "point") == 0) {
		ret =  NewElement(EXobservationID, OFFpointID, SIZEpointID, number, comp, FUNC_NONE, NULLPtr);
	} else {
		yyerror("Unknown observation specifier: %s", type);
	}

	return ret;
} // End of AddObservation

static int AddVRF(direction_t direction, uint16_t comp, uint64_t number) {

	int ret = -1;
	switch(direction) {
		case DIR_INGRESS:
			ret =  NewElement(EXvrfID, OFFingressVrf, SIZEingressVrf, number, comp, FUNC_NONE, NULLPtr);
			break;
		case DIR_EGRESS:
			ret =  NewElement(EXvrfID, OFFegressVrf, SIZEegressVrf, number, comp, FUNC_NONE, NULLPtr);
			break;
		default:
			yyerror("Unknown vrf specifier");
	}

	return ret;
} // End of AddVRF

static int AddPFString(char *type, char *arg) {

	int ret = -1;
	if (strcasecmp(type, "action") == 0) {
		int pfAction = pfActionNr(arg);
		if ( pfAction < 0 ) {
				yyerror("Invalid pf action: %s", arg);
				printf("Possible pf action values: ");
				pfListActions();
			} else {
				ret = NewElement(EXpfinfoID, OFFpfAction, SIZEpfAction, pfAction, CMP_EQ, FUNC_NONE, NULLPtr);
			}
	} else if (strcasecmp(type, "reason") == 0) {
		int pfReason = pfReasonNr(arg);
			if ( pfReason < 0 ) {
				yyerror("Invalid pf reason: %s", arg);
				printf("Possible pf reason values: ");
				pfListReasons();
			} else {
				ret = NewElement(EXpfinfoID, OFFpfReason, SIZEpfReason, pfReason, CMP_EQ, FUNC_NONE, NULLPtr);
			}
	} else if (strcasecmp(type, "dir") == 0) {
		int pfDir = strcasecmp(arg, "in") == 0 ? 1: 0;
		ret = NewElement(EXpfinfoID, OFFpfDir, SIZEpfDir, pfDir, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(type, "interface") == 0) {
		data_t data = {.dataPtr=strdup(arg)};
		ret = NewElement(EXpfinfoID, OFFpfIfName, SIZEpfIfName, 0, CMP_STRING, FUNC_NONE, data);
	} else {
		yyerror("Invalid pf argument: %s", type);
	}
	return ret;
} // End of AddPFString

static int AddPFNumber(char *type, uint16_t comp, uint64_t number) {

	int ret = -1;
	if (strcasecmp(type, "rule") == 0) {
		ret = NewElement(EXpfinfoID, OFFpfRuleNr, SIZEpfRuleNr, number, comp, FUNC_NONE, NULLPtr);
	} else {
		yyerror("Invalid pf argument: %s", type);
	}

	return ret;
} // End of AddPFNumber

static int AddIP(direction_t direction, char *IPstr) {

	int lookupMode = STRICT_IP;
	switch ( direction ) {
			case DIR_SRC:
			case DIR_DST:
			case DIR_UNSPEC:
				lookupMode = ALLOW_LOOKUP;
				break;
			default:
				lookupMode = STRICT_IP;
	} // End of switch

	int numIP = parseIP(IPstr, ipStack, lookupMode);
	if ( numIP <= 0)  {
		yyerror("Can not parse/lookup %s to an IP address", IPstr);
		return -1;
	}

	int ret = -1;
	switch ( direction ) {
		case DIR_SRC:
		case DIR_DST:
		case DIR_SRC_NAT:
		case DIR_DST_NAT:
		case DIR_SRC_TUN:
		case DIR_DST_TUN:
		case DIR_NEXT:
		case BGP_NEXT:
		case SRC_ROUTER:
			ret = ChainHosts(ipStack, numIP, direction);
			break;
		case DIR_UNSPEC: {
			uint32_t src = ChainHosts(ipStack, numIP, DIR_SRC);
			uint32_t dst = ChainHosts(ipStack, numIP, DIR_DST);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_NAT: {
			uint32_t src = ChainHosts(ipStack, numIP, DIR_SRC_NAT);
			uint32_t dst = ChainHosts(ipStack, numIP, DIR_DST_NAT);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_TUN: {
			uint32_t src = ChainHosts(ipStack, numIP, DIR_SRC_TUN);
			uint32_t dst = ChainHosts(ipStack, numIP, DIR_DST_TUN);
			ret = Connect_OR(src, dst);
			} break;
		default:
			yyerror("Unknown direction for IP address");
	} // End of switch

	return ret;
} // End of AddIP

static int AddNet(direction_t direction, char *IPstr, char *maskStr) {
	
	int numIP = parseIP(IPstr, ipStack, STRICT_IP);
	if (numIP <= 0)  {
		yyerror("Can not parse/lookup %s to an IP address", IPstr);
		return -1;
	}

	ipStack_t	mask;
	numIP = parseIP(maskStr, &mask, STRICT_IP);
	if (numIP <= 0)  {
		yyerror("Can not parse %s as IP mask", maskStr);
		return -1;
	}

	if (ipStack[0].af != PF_INET || mask.af != PF_INET) {
		yyerror("Net address %s and netmask: %s must be IPv4", IPstr, maskStr);
		return -1;
	}

	data_t data = {.dataVal = mask.ipaddr[1]};

	int ret = -1;
	switch ( direction ) {
		case DIR_SRC:
		case DIR_DST:
		case DIR_SRC_NAT:
		case DIR_DST_NAT:
		case DIR_SRC_TUN:
		case DIR_DST_TUN:
		case DIR_NEXT:
		case BGP_NEXT:
		case SRC_ROUTER:
			ret = NewIPElement(&ipStack[0], direction, CMP_NET, &data);
			break;
		case DIR_UNSPEC: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC, CMP_NET, &data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST, CMP_NET, &data);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_NAT: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC_NAT, CMP_NET, &data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST_NAT, CMP_NET, &data);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_TUN: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC_TUN, CMP_NET, &data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST_TUN, CMP_NET, &data);
			ret = Connect_OR(src, dst);
			} break;
		default:
			yyerror("Unknown direction for IP address");
	} // End of switch

	return ret;
} // End of AddNet

static int AddNetPrefix(direction_t direction, char *IPstr, uint64_t prefix) {
	int numIP = parseIP(IPstr, ipStack, STRICT_IP);
	if (numIP <= 0)  {
		yyerror("Can not parse/lookup %s to an IP address", IPstr);
		return -1;
	}

	data_t data[2];
	if (ipStack[0].af == PF_INET) {
		// IPv4 
		if (prefix >32 ) {
			yyerror("Prefix %llu out of range for IPv4 address", prefix);
			return -1;
		}
		data[0].dataVal = 0xffffffffffffffffLL << (32 - prefix);
	} else {
		// IPv6
		if (prefix >128 ) {
			yyerror("Prefix %llu out of range for IPv6 address", prefix);
			return -1;
		}
		if ( prefix > 64 ) {
			data[0].dataVal = 0xffffffffffffffffLL;
			data[1].dataVal = 0xffffffffffffffffLL << (128 - prefix);
		} else {
			data[0].dataVal = 0xffffffffffffffffLL << (64 - prefix);
			data[1].dataVal = 0;
		}
	}

	int ret = -1;
	switch (direction) {
		case DIR_SRC:
		case DIR_DST:
		case DIR_SRC_NAT:
		case DIR_DST_NAT:
		case DIR_SRC_TUN:
		case DIR_DST_TUN:
		case DIR_NEXT:
		case BGP_NEXT:
		case SRC_ROUTER:
			ret = NewIPElement(&ipStack[0], direction, CMP_NET, data);
			break;
		case DIR_UNSPEC: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC, CMP_NET, data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST, CMP_NET, data);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_NAT: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC_NAT, CMP_NET, data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST_NAT, CMP_NET, data);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_TUN: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC_TUN, CMP_NET, data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST_TUN, CMP_NET, data);
			ret = Connect_OR(src, dst);
			} break;
		default:
			yyerror("Unknown direction for IP address");
	} // End of switch

	return ret;
} // End of AddNetPrefix

static int AddIPlist(direction_t direction, void *IPlist) {
	int ret = -1;
	data_t IPlistData = {IPlist};
	switch ( direction ) {
		case DIR_SRC:
			ret = Connect_OR(
				NewElement(EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXipv6FlowID, OFFsrc6Addr, SIZEsrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_DST:
			ret = Connect_OR(
				NewElement(EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_SRC_NAT:
			ret = Connect_OR(
				NewElement(EXnatXlateIPv4ID, OFFxlateSrc4Addr, SIZExlateSrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXnatXlateIPv6ID, OFFxlateSrc6Addr, SIZExlateSrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_DST_NAT:
			ret = Connect_OR(
				NewElement(EXnatXlateIPv4ID, OFFxlateDst4Addr, SIZExlateDst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXnatXlateIPv6ID, OFFxlateDst6Addr, SIZExlateDst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_SRC_TUN:
			ret = Connect_OR(
				NewElement(EXtunIPv4ID, OFFtunSrc4Addr, SIZEtunSrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXtunIPv6ID, OFFtunSrc6Addr, SIZEtunSrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_DST_TUN:
			ret = Connect_OR(
				NewElement(EXtunIPv4ID, OFFtunDst4Addr, SIZEtunDst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXtunIPv6ID, OFFtunDst6Addr, SIZEtunDst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_NEXT:
			ret = Connect_OR(
				NewElement(EXipNextHopV4ID, OFFNextHopV4IP, SIZENextHopV4IP, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXipNextHopV6ID, OFFNextHopV6IP, SIZENextHopV6IP, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_UNSPEC: {
			int v4 = Connect_OR(
				NewElement(EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData) 
			);
			int v6 = Connect_OR(
				NewElement(EXipv6FlowID, OFFsrc6Addr, SIZEsrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData),
				NewElement(EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			ret = Connect_OR(v4, v6);
		} break;
		case DIR_UNSPEC_NAT: {
			int v4 = Connect_OR(
				NewElement(EXnatXlateIPv4ID, OFFxlateSrc4Addr, SIZExlateSrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXnatXlateIPv4ID, OFFxlateDst4Addr, SIZExlateDst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData) 
			);
			int v6 = Connect_OR(
				NewElement(EXnatXlateIPv6ID, OFFxlateSrc6Addr, SIZExlateSrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData),
				NewElement(EXnatXlateIPv6ID, OFFxlateDst6Addr, SIZExlateDst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			ret = Connect_OR(v4, v6);
		} break;
		case DIR_UNSPEC_TUN: {
			int v4 = Connect_OR(
				NewElement(EXtunIPv4ID, OFFtunSrc4Addr, SIZEtunSrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXtunIPv4ID, OFFtunDst4Addr, SIZEtunDst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			int v6 = Connect_OR(
				NewElement(EXtunIPv6ID, OFFtunSrc6Addr, SIZEtunSrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData),
				NewElement(EXtunIPv6ID, OFFtunDst6Addr, SIZEtunDst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			ret = Connect_OR(v4, v6);
		} break;
		default:
			yyerror("Unknown direction for IP list");
	}

	return ret;
} // AddIPlist

static struct IPListNode *mkNode(ipStack_t ipStack, int64_t prefix) {

	struct IPListNode *node = malloc(sizeof(struct IPListNode));
	if (node == NULL) {
		yyerror("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return NULL;
	}

	node->ip[0] = ipStack.ipaddr[0];
	node->ip[1] = ipStack.ipaddr[1];
	node->mask[0] = 0xffffffffffffffffLL;
	node->mask[1] = 0xffffffffffffffffLL;

	if ( prefix > 0 ) {
		if (ipStack.af == PF_INET) {
		// IPv4 
			if (prefix >32 ) {
				yyerror("Prefix %llu out of range for IPv4 address", prefix);
				return NULL;
			}
			node->mask[0] = 0;
			node->mask[1] = 0xffffffffffffffffLL << (32 - prefix);
		} else {
			// IPv6
			if (prefix >128 ) {
				yyerror("Prefix %llu out of range for IPv6 address", prefix);
				return NULL;
			}
			if ( prefix > 64 ) {
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL << (128 - prefix);
			} else {
				node->mask[0] = 0xffffffffffffffffLL << (64 - prefix);
				node->mask[1] = 0;
			}
		}
	}
	return node;
}

static void *NewIplist(char *IPstr, int prefix) {
	IPlist_t *root = malloc(sizeof(IPlist_t));
	if (root == NULL) {
		yyerror("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return NULL;
	}
	RB_INIT(root);

	int numIP = parseIP(IPstr, ipStack, ALLOW_LOOKUP);
	if ( numIP <= 0 ) {
		yyerror("Can not parse/resolve %s to an IP address", IPstr);
		free(root);
		return NULL;
	}
		
	for (int i=0; i<numIP; i++ ) {
	  struct IPListNode *node = mkNode(ipStack[i], prefix);
		if ( node ) {
			RB_INSERT(IPtree, root, node);
		} else {
			free(root);
			return NULL;
		}
	}

	return root;
} // End of NewIPlist

static int InsertIPlist(void *IPlist, char *IPstr, int64_t prefix) {
	int numIP = parseIP(IPstr, ipStack, ALLOW_LOOKUP);
	if ( numIP <= 0 ) {
		// ret == - 2 means lookup failure
		yyerror("Can not parse/resolve %s to an IP address", IPstr);
		return 0;
	}

	for (int i=0; i<numIP; i++ ) {
		struct IPListNode *node = mkNode(ipStack[i], prefix);
		if ( node ) {
			RB_INSERT(IPtree, (IPlist_t *)IPlist, node);
		} else {
			return 0;
		}
	}
	return 1;
} // End of InsertIPlist

static void *NewU64list(uint64_t num) {
	U64List_t *root = malloc(sizeof(U64List_t));
	if (root == NULL) {
		yyerror("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return NULL;
	}
	RB_INIT(root);

  struct U64ListNode *node;
	if ((node = malloc(sizeof(struct U64ListNode))) == NULL) {
		yyerror("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		free(root);
		return NULL;
	}
	node->value = num;
	RB_INSERT(U64tree, root, node);

	return root;
} // End of NewU64list

static int InsertU64list(void *U64list, uint64_t num) {
	
	struct U64ListNode *node;
	if ((node = malloc(sizeof(struct U64ListNode))) == NULL) {
		yyerror("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return 0;
	}
	node->value = num;
	RB_INSERT(U64tree, U64list, node);

	return 1;
} // End of InsertU64list

static int AddPortList(direction_t direction, void *U64List) {

	// check, that each element is a valid port number
	struct U64ListNode *node;
	RB_FOREACH(node, U64tree, (U64List_t *)U64List) {
		if ( node->value > 65535 ) {
			yyerror("Port: %llu outside of range 0..65535", node->value);
			return -1;
		}
	}

	data_t U64ListPtr = {U64List};
	int ret = -1;
  switch ( direction ) {
	  case DIR_SRC:
		  ret = NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_DST:
		  ret = NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_UNSPEC:
		  ret = Connect_OR(
			  NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr),
				NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr)
		  );
		  break;
		case DIR_SRC_NAT:
		  ret = NewElement(EXnatXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_DST_NAT:
		  ret = NewElement(EXnatXlatePortID, OFFxlateDstPort, SIZExlateDstPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_UNSPEC_NAT:
		  ret = Connect_OR(
		  	NewElement(EXnatXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr),
		  	NewElement(EXnatXlatePortID, OFFxlateDstPort, SIZExlateDstPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr )
		  );
		  break;
	  default:
		  yyerror("Unknown direction");
  } // End switch

	return ret;
} // AddPortList

static int AddASList(direction_t direction, void *U64List) {

	// check, that each element is a valid AS number
	struct U64ListNode *node;
	RB_FOREACH(node, U64tree, (U64List_t *)U64List) {
		if ( node->value > 0xFFFFFFFFLL ) {
			yyerror("AS: %llu outside of range 32bit", node->value);
			return -1;
		}
	}

	data_t U64ListPtr = {U64List};
	int ret = -1;
  switch ( direction ) {
	  case DIR_SRC:
		  ret = NewElement(EXasRoutingID, OFFsrcAS, SIZEsrcAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_DST:
		  ret = NewElement(EXasRoutingID, OFFdstAS, SIZEdstAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_UNSPEC:
		  ret = Connect_OR(
			  NewElement(EXasRoutingID, OFFsrcAS, SIZEsrcAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr),
			  NewElement(EXasRoutingID, OFFdstAS, SIZEdstAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr)
		  );
		  break;
		case DIR_NEXT:
		  ret = NewElement(EXasAdjacentID, OFFnextAdjacentAS, SIZEnextAdjacentAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
			break;
		case DIR_PREV:
		  ret = NewElement(EXasAdjacentID, OFFprevAdjacentAS, SIZEprevAdjacentAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  default:
			yyerror("Unknown direction");
  } // End of switch

	return ret;
} // AddASList

static int AddInterfaceNumber(direction_t direction, uint64_t num) {
	if ( num > 0xffffffffLL ) {
		yyerror("Interface number out of range 0..2^32");
		return -1;
	}

	int ret = -1;
	switch ( direction ) {
		case DIR_UNSPEC:
			ret = Connect_OR(
				NewElement(EXflowMiscID, OFFinput, SIZEinput, num, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXflowMiscID, OFFoutput, SIZEoutput, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_IN: 
			ret = NewElement(EXflowMiscID, OFFinput, SIZEinput, num, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_OUT: 
			ret = NewElement(EXflowMiscID, OFFoutput, SIZEoutput, num, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		default:
			yyerror("Unknown interface direction");
	} // End of switch

	return ret;
} // End of AddInterfaceNumber

static int AddVlanNumber(direction_t direction, uint64_t num) {
	if ( num > 0xffffffffLL ) {
		yyerror("Vlan number out of range 32bit");
		return -1;
	}

	int ret = -1;
	switch ( direction ) {
		case DIR_UNSPEC: {
			int src = Connect_OR(
			  NewElement(EXvLanID, OFFsrcVlan, SIZEsrcVlan, num, CMP_EQ, FUNC_NONE, NULLPtr),
			  NewElement(EXlayer2ID, OFFvlanID, SIZEvlanID, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			int dst = Connect_OR(
			  NewElement(EXvLanID, OFFdstVlan, SIZEdstVlan, num, CMP_EQ, FUNC_NONE, NULLPtr),
			  NewElement(EXlayer2ID, OFFpostVlanID, SIZEpostVlanID, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			ret = Connect_OR(src,dst);
			} break;
		case DIR_SRC: 
			ret = Connect_OR(
			  NewElement(EXvLanID, OFFsrcVlan, SIZEsrcVlan, num, CMP_EQ, FUNC_NONE, NULLPtr),
			  NewElement(EXlayer2ID, OFFvlanID, SIZEvlanID, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_DST: 
			ret = Connect_OR(
			  NewElement(EXvLanID, OFFdstVlan, SIZEdstVlan, num, CMP_EQ, FUNC_NONE, NULLPtr),
			  NewElement(EXlayer2ID, OFFpostVlanID, SIZEpostVlanID, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		default:
			yyerror("Unknown vlan direction");
	} // End of switch

	return ret;
} // End of AddVlanNumber

static int AddAsNumber(direction_t direction, uint16_t comp, uint64_t as) {
	if (as > UINT32_MAX ) {
		yyerror("AS number of range");
		return -1;
  }

	int ret = -1;
  switch ( direction ) {
	  case DIR_SRC:
		  ret = NewElement(EXasRoutingID, OFFsrcAS, SIZEsrcAS, as, comp, FUNC_MMAS_LOOKUP, (data_t){.dataVal = OFFsrcAS});
		  break;
	  case DIR_DST:
		  ret = NewElement(EXasRoutingID, OFFdstAS, SIZEdstAS, as, comp, FUNC_MMAS_LOOKUP , (data_t){.dataVal = OFFdstAS});
		  break;
	  case DIR_UNSPEC:
		  ret = Connect_OR(
			  NewElement(EXasRoutingID, OFFsrcAS, SIZEsrcAS, as, comp, FUNC_MMAS_LOOKUP, (data_t){.dataVal = OFFsrcAS}),
			  NewElement(EXasRoutingID, OFFdstAS, SIZEdstAS, as, comp, FUNC_MMAS_LOOKUP ,(data_t){.dataVal = OFFdstAS} )
		  );
			break;
		case DIR_NEXT:
		  ret = NewElement(EXasAdjacentID, OFFnextAdjacentAS, SIZEnextAdjacentAS, as, comp, FUNC_MMAS_LOOKUP, NULLPtr);
			break;
		case DIR_PREV:
		  ret = NewElement(EXasAdjacentID, OFFprevAdjacentAS, SIZEprevAdjacentAS, as, comp, FUNC_MMAS_LOOKUP, NULLPtr);
		  break;
	  default:
			yyerror("Unknown direction");
  } // End of switch

	return ret;
} // End of AddAsNumber

static int AddMaskNumber(direction_t direction, uint64_t num) {
	if ( num > 255 ) {
		yyerror("Mas %d out of range 0..255", num);
		return -1;
	}

	int ret = -1;
	switch ( direction ) {
		case DIR_UNSPEC:
			ret = Connect_OR(
				NewElement(EXflowMiscID, OFFsrcMask, SIZEsrcMask, num, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXflowMiscID, OFFdstMask, SIZEdstMask, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_SRC: 
			ret = NewElement(EXflowMiscID, OFFsrcMask, SIZEsrcMask, num, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_DST: 
			ret = NewElement(EXflowMiscID, OFFdstMask, SIZEdstMask, num, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		default:
			yyerror("Invalid direction for mask");
	} // End of switch

	return ret;
} // End of AddMaskNumber

static int AddFlowDir(direction_t direction, int64_t dirNum) {

	int ret = -1;
	switch (direction) {
		case DIR_INGRESS:
	  	ret = NewElement(EXflowMiscID, OFFdir, SIZEdir, 0, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_EGRESS:
	  	ret = NewElement(EXflowMiscID, OFFdir, SIZEdir, 1, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_UNSPEC:
			if (dirNum != 0 && dirNum != 1) {
	 			yyerror("Unknown flowdir: %d", dirNum);
			} else {
	  		ret = NewElement(EXflowMiscID, OFFdir, SIZEdir, dirNum, CMP_EQ, FUNC_NONE, NULLPtr);
			}
			break;
		default:
	 			yyerror("Unknown flowdir");
	}

	return ret;
} // End of AddFlowDirString

