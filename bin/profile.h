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
 *  $Id: profile.h 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *      
*/

#ifndef _PROFILE_H
#define _PROFILE_H 1

typedef struct profile_param_info_s {
	struct profile_param_info_s *next;
	int		profiletype;
	char	*profilegroup;
	char	*profilename;
	char	*channelname;
	char	*channel_sourcelist;
} profile_param_info_t;

typedef struct profile_channel_info_s {
	FilterEngine_data_t	*engine;
	char				*group;
	char				*profile;
	char				*channel;
	char				*ofile;			// tmp output file
	char				*wfile;			// final filename
	char				*rrdfile;		// rrd filename for update
	char				*dirstat_path;	// pathname for dirstat file
	nffile_t			*nffile;
	stat_record_t		stat_record;
	xstat_t				*xstat;
	int					type;
	dirstat_t 			*dirstat;
} profile_channel_info_t;

profile_channel_info_t	*GetProfiles(void);

unsigned int InitChannels(char *profile_datadir, char *profile_statdir, profile_param_info_t *profile_list, 
	char *filterfile, char *filename, int subdir_index, int veryfy_only, int compress, int do_xstat );

profile_channel_info_t	*GetChannelInfoList(void);

void CloseChannels (time_t tslot, int compress);

void UpdateRRD( time_t tslot, profile_channel_info_t *channel );

#endif //_PROFILE_H
