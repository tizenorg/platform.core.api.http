Name:		capi-network-http
Summary:	Http Framework
Version:	0.0.9
Release:	0
Group:		System/Network
License:	Apache-2.0
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(capi-base-common)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(gio-2.0)
BuildRequires:	pkgconfig(capi-network-connection)
BuildRequires:	pkgconfig(libcurl)
BuildRequires:	pkgconfig(openssl)
BuildRequires:	pkgconfig(cynara-client)
BuildRequires:	cmake
Requires(post):		/sbin/ldconfig
Requires(postun):	/sbin/ldconfig

%description
Http framework library for CAPI

%package devel
Summary:	Development package for Http framework library
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}
%description devel
Development package for Http framework library

%prep
%setup -q

%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%cmake -DCMAKE_BUILD_TYPE="Private" \
%ifarch %{arm}
	-DCMAKE_BUILD_TYPE="Private" -DARCH=arm \
%else
%if 0%{?simulator}
	-DCMAKE_BUILD_TYPE="Private" -DARCH=emul \
%else
	-DCMAKE_BUILD_TYPE="Private" -DARCH=i586 \
%endif
%endif
	.

make %{?_smp_mflags}


%install
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/capi-network-http
cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/capi-network-http-devel

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest capi-network-http.manifest
%defattr(-,root,root,-)
%{_libdir}/*.so.*
/usr/share/license/capi-network-http
%{_bindir}/http_test
%ifarch %{arm}
/etc/config/connectivity/sysinfo-http.xml
%else
%if 0%{?simulator}
# Noop
%else
/etc/config/connectivity/sysinfo-http.xml
%endif
%endif

%files devel
%defattr(-,root,root,-)
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/*.so
/usr/share/license/capi-network-http-devel
