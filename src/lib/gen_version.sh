#!/bin/sh

echo Creating vcs_track.h
f="vcs_track.h"
date=$(git show -s --format=%ci)

if [ -d ../../.git ]; then
  if [ -x "$(command -v git)" ]; then
    hash=$(git rev-parse --short HEAD)
  else
    hash="unkn"
  fi
else
  hash="release"
fi

echo \#ifndef __VCS_TRACK_H__ >$f
echo \#define __VCS_TRACK_H__ >>$f
echo \/\/THIS FILE IS AUTO GENERATED >>$f
echo \/\/DO NOT TRACK THIS FILE WITH THE VCS >>$f
echo \#define VCS_TRACK_DATE \"$date\" >>$f
echo \#define VCS_TRACK_HASH \"$hash\" >>$f

echo \#endif >>$f
