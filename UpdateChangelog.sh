#!/bin/sh

git log --pretty="- %h %as %d %s" > ChangeLog
