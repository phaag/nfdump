#!/bin/sh
#  Copyright (c) 2023-2024, Peter Haag
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   * Neither the name of the author nor the names of its contributors may be
#     used to endorse or promote products derived from this software without
#     specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.

echo Creating vcs_track.h
f="vcs_track.h"

if [ -d ../../.git ]; then
  # git clone - should have git command too
  if [ -x "$(command -v git)" ]; then
    hash=$(git rev-parse --short HEAD)
    date=$(git show -s --format=%ci)
  else
    # has git directory but no git command ..
    hash="git"
    date=$(date +'%c')
  fi
else
  # no git directory - most likely release - zip or tarball
  hash="release"
  date="Fri Apr 18 15:22:34 CEST 2025"
fi

echo \#ifndef __VCS_TRACK_H__ >$f
echo \#define __VCS_TRACK_H__ >>$f
echo \/\/THIS FILE IS AUTO GENERATED >>$f
echo \/\/DO NOT TRACK THIS FILE WITH THE VCS >>$f
echo \#define VCS_TRACK_DATE \"$date\" >>$f
echo \#define VCS_TRACK_HASH \"$hash\" >>$f

echo \#endif >>$f
