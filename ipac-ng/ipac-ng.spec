Summary: ipac-ng
Name: ipac-ng
Version: 1.28
Release: 1
Copyright: GPL
Group: System Environment/Daemons
URL: http://sourceforge.net/projects/ipac-ng/
Source: ftp://sibinet.com/pub/ipac-ng/%{name}-%{version}.tar.bz2
Packager: Alex Miller <asmm@canada.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildPreReq: gdbm-devel, bison, flex
Prereq: perl
Requires: gdbm, perl

%description
ipac is a package which is designed to gather, summarize and nicely
output the IP accounting data. ipac make summaries and graphs as ascii
text and/or images with graphs.

%prep
%setup -q -n %{name}-%{version}
CFLAGS="$RPM_OPT_FLAGS" CXXFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%{_prefix} --mandir=%{_mandir}

%build
make DESTDIR=$RPM_BUILD_ROOT all

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install
mkdir -p $RPM_BUILD_ROOT/etc
mkdir -p $RPM_BUILD_ROOT/etc/ipac-ng
mkdir -p $RPM_BUILD_ROOT/var/www/cgi-bin
#mkdir -p $RPM_BUILD_ROOT/var/www/html/stat
mkdir -p $RPM_BUILD_ROOT/var/lib/ipac
install -m 644 contrib/sample_configs/ipac.conf $RPM_BUILD_ROOT/etc/ipac-ng/ipac.conf
install -m 644 contrib/sample_configs/rules.conf.ipchains $RPM_BUILD_ROOT/etc/ipac-ng/rules.conf.ipchains
install -m 644 contrib/sample_configs/rules.conf.iptables $RPM_BUILD_ROOT/etc/ipac-ng/rules.conf.iptables
#install -m 644 html/stat/index.html $RPM_BUILD_ROOT/var/www/html/stat/index.html
#install -m 644 html/cgi-bin/.htaccess $RPM_BUILD_ROOT/var/www/cgi-bin/.htaccess
#install -m 755 html/cgi-bin/* $RPM_BUILD_ROOT/var/www/cgi-bin
touch $RPM_BUILD_ROOT/var/lib/ipac/flag

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{name}-%{version}

%post
echo " * Installation complete. Please, read files in" %{_defaultdocdir}/%{name}-%{version}

%files
%defattr(-,root,root)
%config(noreplace) /etc/ipac-ng/ipac.conf
%config(noreplace) /etc/ipac-ng/rules.conf.ipchains
%config(noreplace) /etc/ipac-ng/rules.conf.iptables
%attr(755,root,root)/usr/sbin/ipacsum
%attr(755,root,root)/usr/sbin/fetchipac
%attr(755,root,root)/usr/sbin/ipac-convert
#%attr(644,nobody,nobody)/var/www/html/stat/index.html
%attr(644,root,root)/var/www/cgi-bin/.htaccess
%attr(755,nobody,nobody)/var/www/cgi-bin/*
%attr(664,apache,nobody)/var/lib/ipac/flag
%dir /var/lib/ipac
%dir /var/www/cgi-bin
#%dir /var/www/html/stat
%doc %attr(644,root,root)CHANGES COPYING README README-NG TODO UPDATE contrib/* postgre.readme ipac-ng.sql
%{_mandir}/man8/*.8.gz

%changelog
* Tue Nov 14 2001 Al Zakharov <kaiser13@mail2000.ru>
- placement of index.html file fixed
- installation of reconfig flag file added
* Mon Oct 15 2001 Al Zakharov <kaiser13@mail2000.ru>
- config file path fixed
- changed to use tmppath
- more requires added
- prereq's added
- ownership of .htaccess changed
* Thu Oct 04 2001 Alex Miller <asmm@canada.com>
- added cgi-bin utilities
- fixed description and %doc attributes
* Wed Oct 03 2001 Alex Miller <asmm@canada.com>
- started package with ipac-ng-1.11
