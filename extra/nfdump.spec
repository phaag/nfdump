Name:		nfdump
Version:	1.8.0
Release:	%mkrel 0
Summary:	NetFlow collecting and processing tools
License:	BSD
Packager:	Richard REY (Rexy)
Group:		Networking/Other
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	lib64rrdtool-devel
BuildRoot:	%{_tmppath}/%{name}-root
Url:		https://github.com/phaag/nfdump

%description
nfdump is a toolset in order to collect and process netflow/ipfix and sflow data
sent from netflow/sflow compatible devices.
The toolset contains several collectors to collect flow data:
- nfcapd supports netflow v1, v5/v7,v9 and IPFIX
- sfcapd support sflow
- nfpcapd converts pcap data read from a host interface or from pcap files.
nfdump is now a multi-threaded program and uses parallel threads mainly for reading, writing and processing flows as well as for sorting.

%prep
rm -rf $RPM_BUILD_ROOT
%setup -q

%build
./autogen.sh
# --enable-nftrack was removed - --enable-nfprofile alone now builds both
# nfprofile and nftrack (src/nfsen/Makefile.am).
%define configure_args --enable-nfprofile --disable-rpath --disable-static
%configure %{configure_args}
%make_build

%install
%make_install
chmod 0644 AUTHORS ChangeLog README.md
rm -f %{buildroot}%{_libdir}/*.la

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%license LICENSE
%doc AUTHORS ChangeLog README.md
%{_bindir}/*
%{_libdir}/*
%{_sysconfdir}/*
%{_mandir}/man1/*
%{_mandir}/man5/*

%changelog
* Mon Aug 24 2026 nfdump
- Version 1.8.0: bump for the 1.8.x nffile V3 / TOML-config release.
  --enable-nftrack no longer exists as its own flag (folded into
  --enable-nfprofile); added the man5 section (nfdump.conf.5, new in
  1.8.x) to the packaged file list.
  librrd remains the only extra BuildRequires nfprofile needs; the other
  new optional 1.8.x features (PCRE2 payload regex, libsodium encryption,
  LZ4/ZSTD/BZ2 compression) are auto-detected by configure and degrade
  gracefully when their -devel packages are absent, so nothing to add here
  unless you want those features guaranteed on for a given build.

* Sun Nov 26 2023 Richard REY <Rexy>
- Version 1.7.3 for ALCASAR 3.6.1
