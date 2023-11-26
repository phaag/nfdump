Name:		nfdump
Version:	1.7.3
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
%define configure_args --enable-nfprofile --enable-nftrack --disable-rpath --disable-static
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

%changelog
* Sun Nov 26 2023 Richard REY <Rexy>
- Version 1.7.3 for ALCASAR 3.6.1
