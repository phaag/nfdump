
dist_man_MANS = nfcapd.1 sfcapd.1 nfdump.1 nfexpire.1 nfreplay.1 nfanon.1
dist_man_MANS += geolookup.1 torlookup.1
dist_man_MANS += nfmeta.1 nfdump.conf.5
dist_man_MANS += nfdump.3

# Optional man pages must always be present in source distributions, but
# should only be installed when the corresponding program is enabled.
EXTRA_DIST = ft2nfdump.1 nfprofile.1 nfpcapd.1
man_MANS =

if BUILD_FT2NFDUMP
man_MANS += ft2nfdump.1
endif

if BUILD_NFPROFILE
man_MANS += nfprofile.1
endif

if BUILD_NFPCAPD
man_MANS += nfpcapd.1
endif
