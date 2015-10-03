/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: haag $
 *
 *  $Id: util.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#ifndef SYSLOG_NAMES
#define SYSLOG_NAMES 1
#endif
#include <syslog.h>
#include <stdarg.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"

/* Global vars */

extern char *CurrentIdent;

enum { NONE, LESS, MORE };

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

/* Function prototypes */
static int check_number(char *s, int len);

static int ParseTime(char *s, time_t *t_start);

uint32_t		twin_first, twin_last;

static int use_syslog = 0;

#ifdef sun
struct _code {
    char    *c_name;
    int c_val;
} facilitynames[] = {
    { "auth", LOG_AUTH },
    { "cron", LOG_CRON },
    { "daemon", LOG_DAEMON },
    { "kern", LOG_KERN },
    { "lpr", LOG_LPR },
    { "mail", LOG_MAIL },
    { "news", LOG_NEWS },
    { "security", LOG_AUTH },       /* DEPRECATED */
    { "syslog", LOG_SYSLOG },
    { "user", LOG_USER },
    { "uucp", LOG_UUCP },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }
};
#endif

/* Functions */

/*
** usleep(3) implemented with select.
*/

void xsleep(long sec) {
	struct timeval tv;

	tv.tv_sec = sec;
	tv.tv_usec = 0;

	select(0, NULL, NULL, NULL, &tv);
}

void EndLog() {
	if ( use_syslog )
		closelog();
} // End of CloseLog

int InitLog(char *name, char *facility) {
int i;
char *logname;

	if ( !facility || strlen(facility) > 32 ) {
		fprintf(stderr, "Invalid syslog facility name '%s'!\n", facility);
		return 0;
	}

	
	i = 0;
	while ( facilitynames[i].c_name && strcasecmp(facilitynames[i].c_name, facility ) != 0 ) {
		i++;
	}

	if ( facilitynames[i].c_name == NULL ) {
		fprintf(stderr, "Invalid syslog facility name '%s'!\n", facility);
		return 0;
	}

	if ( (logname = strrchr(name , '/')) != 0 ) {
		logname++;
	} else {
		logname = name;
	}
	openlog(logname, LOG_CONS|LOG_PID, facilitynames[i].c_val);
	use_syslog = 1;

	return 1;

} // End of InitLog

/* 
 * some modules are needed for daemon code as well as normal stdio code 
 * therefore a generic LogError is defined, which maps in this case
 * to stderr
 */
void LogError(char *format, ...) {
va_list var_args;
char string[512];

	if ( use_syslog ) {
		va_start(var_args, format);
		vsnprintf(string, 511, format, var_args);
		va_end(var_args);
		syslog(LOG_ERR, "%s", string);
		dbg_printf("%s\n", string);
	} else {
		va_start(var_args, format);
		vsnprintf(string, 511, format, var_args);
		fprintf(stderr, "%s\n", string);
		va_end(var_args);
	}
	
} // End of LogError

void LogInfo(char *format, ...) {
va_list var_args;
char string[512];

	if ( use_syslog ) {
		va_start(var_args, format);
		vsnprintf(string, 511, format, var_args);
		va_end(var_args);
		syslog(LOG_INFO, "%s", string);
		dbg_printf("%s\n", string);
	} else {
		va_start(var_args, format);
		vsnprintf(string, 511, format, var_args);
		fprintf(stderr, "%s\n", string);
		va_end(var_args);
	}
	
} // End of LogInfo

static int check_number(char *s, int len) {
int i;
int l = strlen(s);

	for ( i=0; i<l; i++ ) {
		if ( s[i] < '0' || s[i] > '9' ) {
			LogError("Time format error at '%s': unexpected character: '%c'.\n", s, s[i]);
			return 0;
		}
	}

	if ( l != len ) {
		LogError("Time format error: '%s' unexpected.\n", s);
		return 0;
	}
	return 1;

} // End of check_number

static int ParseTime(char *s, time_t *t_start ) {
struct tm ts;
int	i;
char *p, *q;


	/* A time string may look like:
	 * yyyy/MM/dd.hh:mm:ss
	 */

	memset((void *)&ts, 0, sizeof(ts));
	ts.tm_isdst = -1;

	p = s;

	// parse year
	q = strchr(p, '/');
	if ( q ) {
		*q++ = 0;
	}
	if ( !check_number(p,4) )
		return 0;
	i = atoi(p);
	if ( i > 2038 || i < 1970 ) {
		LogError("Year out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_year = i - 1900;
	if ( !q ) {
		ts.tm_mday = 1;
		*t_start = mktime(&ts);
		return 1;
	}

	// parse month
	p = q;
	q = strchr(p, '/');
	if ( q ) 
		*q++ = 0;
	if ( !check_number(p,2) ) 
		return 0;
	i = atoi(p);
	if ( i < 1 || i > 12 ) {
		LogError("Month out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_mon = i - 1;
	if ( !q ) {
		ts.tm_mday = 1;
		*t_start   = mktime(&ts);
		return 1;
	}

	// Parse day
	p = q;
	q = strchr(p, '.');
	if ( q ) 
		*q++ = 0;
	if ( !check_number(p,2) ) 
		return 0;
	i = atoi(p);
	if ( i < 1 || i > 31 ) {
		LogError("Day out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_mday = i;
	if ( !q ) {
		*t_start = mktime(&ts);
		return 1;
	}

	// Parse hour
	p = q;
	q = strchr(p, ':');
	if ( q ) 
		*q++ = 0;
	if ( !check_number(p,2) ) 
		return 0;
	i = atoi(p);
	if ( i < 0 || i > 23 ) {
		LogError("Hour out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_hour = i;
	if ( !q ) {
		*t_start = mktime(&ts);
		return 1;
	}

	// Parse minute
	p = q;
	q = strchr(p, ':');
	if ( q ) 
		*q++ = 0;
	if ( !check_number(p,2) ) 
		return 0;
	i = atoi(p);
	if ( i < 0 || i > 59 ) {
		LogError("Minute out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_min = i;
	if ( !q ) {
		*t_start = mktime(&ts);
		return 1;
	}

	// Parse second
	p = q;
	if ( !check_number(p,2) ) 
		return 0;
	i = atoi(p);
	if ( i < 0 || i > 59 ) {
		LogError("Seconds out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_sec = i;
	*t_start = mktime(&ts);
	return 1;

} // End of ParseTime


int ScanTimeFrame(char *tstring, time_t *t_start, time_t *t_end) {
char *p;

	if ( !tstring ) {
		fprintf(stderr,"Time Window format error '%s'\n", tstring);
		return 0;
	}

	// check for delta time window
	if ( tstring[0] == '-' || tstring[0] == '+' ) {
		if ( !twin_first || !twin_last ) {
			fprintf(stderr,"Time Window error: No time slot information available\n");
			return 0;
		}

		if ( tstring[0] == '-' ) {
			*t_start = twin_last + atoi(tstring);
			*t_end	 = twin_last;
			return 1;
		}
		
		if ( tstring[0] == '+' ) {
			*t_start = twin_first;
			*t_end	 = twin_first + atoi(tstring);
			return 1;
		}
	}

	if ( strlen(tstring) < 4 ) {
		fprintf(stderr,"Time Window format error '%s'\n", tstring);
		return 0;
	}
	if ( (p = strchr(tstring, '-') ) == NULL ) {
		ParseTime(tstring, t_start);
		*t_end = 0xFFFFFFFF;
	} else {
		*p++ = 0;
		ParseTime(tstring, t_start);
		ParseTime(p, t_end);
	}

	return *t_start == 0 || *t_end == 0 ? 0 : 1;

} // End of ScanTimeFrame

char *TimeString(time_t start, time_t end) {
static char datestr[255];
char t1[64], t2[64];
struct tm	*tbuff;

	if ( start ) {
		tbuff = localtime(&start);
		if ( !tbuff ) {
			perror("Error time convert");
			exit(250);
		}
		strftime(t1, 63, "%Y-%m-%d %H:%M:%S", tbuff);

		tbuff = localtime(&end);
		if ( !tbuff ) {
			perror("Error time convert");
			exit(250);
		}
		strftime(t2, 63, "%Y-%m-%d %H:%M:%S", tbuff);

		snprintf(datestr, 254, "%s - %s", t1, t2);
	} else {
		snprintf(datestr, 254, "Time Window unknown");
	}
	datestr[254] = 0;
	return datestr;
}

char *UNIX2ISO(time_t t) {
struct tm	*when;
static char timestring[16];

	when = localtime(&t);
	when->tm_isdst = -1;
	snprintf(timestring, 15, "%i%02i%02i%02i%02i", 
		when->tm_year + 1900, when->tm_mon + 1, when->tm_mday, when->tm_hour, when->tm_min);
	timestring[15] = '\0';

	return timestring;

} // End of UNIX2ISO

time_t ISO2UNIX(char *timestring) {
char c, *p;
struct tm	when;
time_t		t;

	// let localtime fill in all default fields such as summer time, TZ etc.
	t = time(NULL);
	localtime_r(&t, &when);
	when.tm_sec  = 0;
	when.tm_wday = 0;
	when.tm_yday = 0;
	when.tm_isdst = -1;

	if ( strlen(timestring) != 12 ) {
		LogError( "Wrong time format '%s'\n", timestring);
		return 0;
	}
	// 2006 05 05 12 00
	// year
	p = timestring;
	c = p[4];
	p[4] = '\0';
	when.tm_year = atoi(p) - 1900;
	p[4] = c;

	// month
	p += 4;
	c = p[2];
	p[2] = '\0';
	when.tm_mon = atoi(p) - 1;
	p[2] = c;

	// day
	p += 2;
	c = p[2];
	p[2] = '\0';
	when.tm_mday = atoi(p);
	p[2] = c;
	
	// hour
	p += 2;
	c = p[2];
	p[2] = '\0';
	when.tm_hour = atoi(p);
	p[2] = c;
	
	// minute
	p += 2;
	when.tm_min = atoi(p);
	
	t = mktime(&when);
	if ( t == -1 ) {
		LogError( "Failed to convert string '%s'\n", timestring);
		return 0;
	} else {
// printf("%s %s", timestring, ctime(&t));
		return t;
	}
		
} // End of ISO2UNIX


void InitStringlist(stringlist_t *list, int block_size) {

	list->list  = NULL;
	list->num_strings = 0;
	list->max_index   = 0;
	list->block_size  = block_size;

} // End of InitStringlist

void InsertString(stringlist_t *list, char *string) {

	if ( !list->list ) {
		list->max_index   = list->block_size;
		list->num_strings = 0;
		list->list = (char **)malloc(list->max_index * sizeof(char *));
		if ( !list->list ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(250);
		}
	}
	list->list[list->num_strings++] = string ? strdup(string) : NULL;

	if ( list->num_strings == list->max_index ) {
		list->max_index += list->block_size;
		list->list = (char **)realloc(list->list, list->max_index * sizeof(char *));
		if ( !list->list ) {
			LogError("realloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(250);
		}
	}

} // End of InsertString

void format_number(uint64_t num, char *s, int scale, int fixed_width) {
double f = num;

	if ( !scale ) {
		snprintf(s, 31, "%llu", (long long unsigned)num);
	} else {

		if ( f >= _1TB ) {
			if ( fixed_width ) 
				snprintf(s, NUMBER_STRING_SIZE-1, "%5.1f T", f / _1TB );
			else 
				snprintf(s, NUMBER_STRING_SIZE-1, "%.1f T", f / _1TB );
		} else if ( f >= _1GB ) {
			if ( fixed_width ) 
				snprintf(s, NUMBER_STRING_SIZE-1, "%5.1f G", f / _1GB );
			else 
				snprintf(s, NUMBER_STRING_SIZE-1, "%.1f G", f / _1GB );
		} else if ( f >= _1MB ) {
			if ( fixed_width ) 
				snprintf(s, NUMBER_STRING_SIZE-1, "%5.1f M", f / _1MB );
			else 
				snprintf(s, NUMBER_STRING_SIZE-1, "%.1f M", f / _1MB );
		} else  {
			if ( fixed_width ) 
				snprintf(s, NUMBER_STRING_SIZE-1, "%4.0f", f );
			else 
				snprintf(s, NUMBER_STRING_SIZE-1, "%.0f", f );
		} 
		s[NUMBER_STRING_SIZE-1] = '\0';
	}

} // End of format_number


