Name: nfdump
Summary: A set of command-line tools to collect and process netflow data
Version: 1.6.16
Release: 1
License: BSD
Group: Applications/System
Source: %{name}-%{version}.tar.gz
BuildRequires: flex
BuildRoot: %{_tmppath}/%{name}-root
Packager: Colin Bloch <fourthdown@gmail.com>
Prefix: /usr
Url: https://github.com/phaag/nfdump

%description
The nfdump tools collect and process netflow data on the command line.
They are part of the NFSEN project, which is explained more detailed at
http://www.terena.nl/tech/task-forces/tf-csirt/meeting12/nfsen-Haag.pdf

%prep
rm -rf $RPM_BUILD_ROOT

%setup -q

%build
./configure --prefix=$RPM_BUILD_ROOT/%{prefix} --libdir=$RPM_BUILD_ROOT/%{_libdir}
make

%install
make install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc INSTALL README.md ToDo BSD-license.txt AUTHORS ChangeLog
%{prefix}/bin/*
%{prefix}/share/man/man1/*
%{_libdir}/*
