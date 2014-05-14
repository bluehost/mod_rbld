Name:           mod_rbld
Summary:        Check remote IP against RBLD
Group:          System Environment/Daemons
Version:        2.0
Release:        1%{?dist}
Distribution:   .ul6
License:        Apache Software License 2.0
URL:            https://github.com/bluehost/mod_rbld
Packager:       %{packager}
Vendor:         %{vendor}
BuildRequires:  httpd-devel >= 2.2, pkgconfig
Requires:       httpd-mmn = %([ -a %{_includedir}/httpd/.mmn ] && %{__cat} %{_includedir}/httpd/.mmn || echo missing)

Source0:        mod_rbld-%{version}.tar.gz
Source1:        mod_rbld.conf

%description
An access module that checks any remote IPv4 address that makes a request by 
querying RBLD, and then returning a forbidden response to the end user if 
RBLD says the IP is blacklisted.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
#rm -rf %{buildroot}
install -D -m755 $RPM_BUILD_DIR/%{name}-%{version}/.libs/mod_rbld.so %{buildroot}/%{_libdir}/httpd/modules/mod_rbld.so

mkdir -p %{buildroot}/%{_sysconfdir}/httpd/conf.d
cp -a %{SOURCE1} %{buildroot}/%{_sysconfdir}/httpd/conf.d/

mkdir -p %{buildroot}/%{_datadir}/mod_rbld
cp -a NOTICE %{buildroot}/%{_datadir}/mod_rbld/NOTICE
cp -a README.TXT %{buildroot}/%{_datadir}/mod_rbld/README.TXT
cp -a LICENSE %{buildroot}/%{_datadir}/mod_rbld/LICENSE
cp -a CHANGES %{buildroot}/%{_datadir}/mod_rbld/CHANGES
cp -a %{SOURCE1} %{buildroot}/%{_datadir}/mod_rbld/mod_rbld.conf.example

%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_libdir}/httpd/modules/mod_rbld.so
%config(noreplace) %{_sysconfdir}/httpd/conf.d/mod_rbld.conf
%{_datadir}/mod_rbld/NOTICE
%{_datadir}/mod_rbld/README.TXT
%{_datadir}/mod_rbld/LICENSE
%{_datadir}/mod_rbld/CHANGES
%{_datadir}/mod_rbld/mod_rbld.conf.example

%changelog
* Tue Jan 14 2014 Erick Cantwell <ecantwell@bluehost.com> 2.0-2
- Change all instances of "mod_rbl" to "mod_rbld" to better refelct what it is
- Updated license to Apache Software License 2.0

* Fri Jan 03 2014 Erick Cantwell <ecantwell@bluehost.com> 2.0-1
- Fixed spec file so that it uses our typical conventions
- Complete rewrite of mod_rbld

* Tue Nov 19 2013 Eric Jacobs <eric@bluehost.com> 1.1-6
- Building against httpd-2.2.26.

* Tue Jul 29 2013 Eric Jacobs <eric@bluehost.com> 1.1-5
- Build against httpd 2.2.25.

* Wed Feb 27 2013 Eric Jacobs <eric@bluehost.com> 1.1-4
- Rebuild against Apache 2.2.24

* Thu Sep 20 2012 Eric Jacobs <ejacobs@bluehost.com> 1.1-3
- Rebuild against Apache 2.2.23

* Wed Feb 01 2012 Sean Jenkins <sean@bluehost.com> 1.1-2
- Rebuild against Apache 2.2.22

* Fri Sep 16 2011 Sean Jenkins <sean@bluehost.com> 1.1-1
- Log that a given ip was blocked due to being on an RBL

* Fri Sep 16 2011 Sean Jenkins <sean@bluehost.com> 1.0-2
- Rebuild against Apache 2.2.21

* Thu Sep 8 2011 Robert Lawrence <robert@bluehost.com> 1.0-1
- Initial RPM build
