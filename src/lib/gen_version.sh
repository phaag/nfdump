#!/bin/sh

echo Creating vcs_track.h
f="vcs_track.h"
date=$(date +'%c')

if [ -d ../../.git ]; then
  # git clone - should have git command too
  if [ -x "$(command -v git)" ]; then
    hash=$(git rev-parse --short HEAD)
    date=$(git show -s --format=%ci)
  else
    # has git directory but no git command ..
    hash="git"
  fi
else
  # no git directory - most likely release
  hash="release"
fi

echo \#ifndef __VCS_TRACK_H__ >$f
echo \#define __VCS_TRACK_H__ >>$f
echo \/\/THIS FILE IS AUTO GENERATED >>$f
echo \/\/DO NOT TRACK THIS FILE WITH THE VCS >>$f
echo \#define VCS_TRACK_DATE \"$date\" >>$f
echo \#define VCS_TRACK_HASH \"$hash\" >>$f

echo \#endif >>$f
