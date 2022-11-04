# Copyright 2022 Wong Hoi Sing Edison <hswong3i@pantarei-design.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

%global debug_package %{nil}

%global _lto_cflags %{?_lto_cflags} -flto=auto -ffat-lto-objects

Name: gnutls
Epoch: 100
Version: 3.7.8
Release: 1%{?dist}
Summary: A low-level cryptographic library
License: LGPL-2.1-or-later
URL: https://github.com/gnutls/gnutls/tags
Source0: %{name}_%{version}.orig.tar.gz
%if 0%{?suse_version} >= 1550 || 0%{?sle_version} >= 150400 || 0%{?fedora_version} >= 35 || 0%{?centos_version} >= 800
BuildRequires: crypto-policies
%endif
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: bison
BuildRequires: brotli-devel
BuildRequires: ca-certificates
BuildRequires: chrpath
BuildRequires: gawk
BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: gettext-devel
BuildRequires: git
BuildRequires: gperf
BuildRequires: gtk-doc
BuildRequires: guile-devel
BuildRequires: libidn2-devel
BuildRequires: libtasn1-devel >= 4.9
BuildRequires: libtasn1-tools
BuildRequires: libtool
BuildRequires: libunistring-devel
BuildRequires: libzstd-devel
BuildRequires: make
BuildRequires: nettle-devel >= 3.6
BuildRequires: openssl-devel
BuildRequires: p11-kit-devel >= 0.23.1
BuildRequires: pkgconfig
BuildRequires: python3-devel
BuildRequires: texinfo >= 4.8
BuildRequires: unbound-devel >= 1.5.10
BuildRequires: unbound-libs
BuildRequires: zlib-devel
%if 0%{?fedora_version} >= 35 || 0%{?centos_version} >= 800
Requires: crypto-policies
%endif
%if !(0%{?suse_version} > 1500) && !(0%{?sle_version} > 150000)
Requires: libtasn1 >= 4.9
Requires: nettle >= 3.6
Requires: p11-kit-trust >= 0.23.1
%endif

%description
GnuTLS is a secure communications library implementing the SSL, TLS and DTLS
protocols and technologies around them. It provides a simple C language
application programming interface (API) to access the secure communications
protocols as well as APIs to parse and write X.509, PKCS #12, OpenPGP and
other required structures.

%prep
%autosetup -T -c -n %{name}_%{version}-%{release}
tar -zx -f %{S:0} --strip-components=1 -C .

%build
sed -i -e 's|sys_lib_dlsearch_path_spec="/lib /usr/lib|sys_lib_dlsearch_path_spec="/lib /usr/lib %{_libdir}|g' configure
rm -f lib/minitasn1/*.c lib/minitasn1/*.h
export CFLAGS="%{optflags}"
export CXXFLAGS="%{optflags}"
export LDFLAGS="-flto=auto -Wl,-z,now -Wl,-z,relro -Wl,--as-needed -ldl"
%configure \
%if 0%{?suse_version} >= 1550 || 0%{?sle_version} >= 150400 || 0%{?fedora_version} >= 35 || 0%{?centos_version} >= 800
    --with-system-priority-file=%{_sysconfdir}/crypto-policies/back-ends/gnutls.config \
    --with-default-priority-string="@SYSTEM" \
%endif
%if 0%{?suse_version} > 1500 || 0%{?sle_version} > 150000
    --with-default-trust-store-dir=%{_localstatedir}/lib/ca-certificates/pem \
%endif
    --disable-bash-tests \
    --disable-doc \
    --disable-full-test-suite \
    --disable-gcc-warnings \
    --disable-gtk-doc \
    --disable-guile \
    --disable-non-suiteb-curves \
    --disable-rpath \
    --disable-silent-rules \
    --disable-static \
    --disable-tests \
    --enable-cxx \
    --enable-libdane \
    --enable-openssl-compatibility \
    --enable-sha1-support \
    --enable-shared \
    --enable-ssl3-support \
    --with-brotli \
    --with-default-trust-store-pkcs11="pkcs11:" \
    --with-unbound-root-key-file=%{_localstatedir}/lib/unbound/root.key \
    --with-zlib \
    --with-zstd \
    --without-tpm
%make_build

%install
%make_build install DESTDIR=%{buildroot}
rm -rf %{buildroot}%{_datadir}/locale
find %{buildroot} -type f -name '*.la' -exec rm -rf {} \;

%check

%if 0%{?suse_version} > 1500 || 0%{?sle_version} > 150000
%package -n libgnutls30
Summary: GNU TLS library - main runtime library
%if 0%{?suse_version} >= 1550 || 0%{?sle_version} >= 150400
Requires: crypto-policies
%endif
Requires: libtasn1 >= 4.9
Requires: nettle >= 3.6
Requires: p11-kit >= 0.23.1

%description -n libgnutls30
The GnuTLS library provides a secure layer over a reliable transport
layer. Currently the GnuTLS library implements the proposed standards
of the IETF's TLS working group.

%package -n libgnutlsxx30
Summary: GNU TLS library - C++ runtime library

%description -n libgnutlsxx30
This package contains the C++ runtime libraries.

%package -n libgnutls-openssl27
Summary: GNU TLS library - OpenSSL wrapper

%description -n libgnutls-openssl27
This package contains the runtime library of the GnuTLS OpenSSL wrapper.

%package -n libgnutls-dane0
Summary: GNU TLS library - DANE security support

%description -n libgnutls-dane0
This package contains the runtime library for DANE (DNS-based
Authentication of Named Entities) support.

%package -n libgnutls-devel
Summary: Development package for the GnuTLS C API
Requires: glibc-devel
Requires: gnutls = %{epoch}:%{version}-%{release}
Requires: libgnutls30 = %{epoch}:%{version}-%{release}
Requires: pkgconfig
Provides: gnutls-devel = %{epoch}:%{version}-%{release}

%description -n libgnutls-devel
Files needed for software development using gnutls.

%package -n libgnutlsxx-devel
Summary: Development package for the GnuTLS C++ API
Requires: libgnutls-devel = %{epoch}:%{version}-%{release}
Requires: libgnutlsxx30 = %{epoch}:%{version}-%{release}
Requires: libstdc++-devel
Requires: pkgconfig

%description -n libgnutlsxx-devel
Files needed for software development using gnutls.

%package -n libgnutls-openssl-devel
Summary: Development package for GnuTLS OpenSSL wrapper
Requires: libgnutls-devel = %{epoch}:%{version}-%{release}
Requires: libgnutls-openssl0 = %{epoch}:%{version}-%{release}
Requires: pkgconfig

%description -n libgnutls-openssl-devel
Files needed for software development using gnutls.

%package -n libgnutls-dane-devel
Summary: Development package for GnuTLS DANE component
Requires: libgnutls-dane0 = %{epoch}:%{version}-%{release}
Requires: libgnutls-devel = %{epoch}:%{version}-%{release}
Requires: pkgconfig

%description -n libgnutls-dane-devel
Files needed for software development using gnutls.

%post -n libgnutls30 -p /sbin/ldconfig
%postun -n libgnutls30 -p /sbin/ldconfig

%post -n libgnutlsxx30 -p /sbin/ldconfig
%postun -n libgnutlsxx30 -p /sbin/ldconfig

%post -n libgnutls-openssl27 -p /sbin/ldconfig
%postun -n libgnutls-openssl27 -p /sbin/ldconfig

%post -n libgnutls-dane0 -p /sbin/ldconfig
%postun -n libgnutls-dane0 -p /sbin/ldconfig

%files
%license LICENSE
%{_bindir}/*

%files -n libgnutls30
%{_libdir}/libgnutls.so.*

%files -n libgnutlsxx30
%{_libdir}/libgnutlsxx.so.*

%files -n libgnutls-openssl27
%{_libdir}/libgnutls-openssl.so.*

%files -n libgnutls-dane0
%{_libdir}/libgnutls-dane.so.*

%files -n libgnutls-devel
%dir %{_includedir}/gnutls
%{_includedir}/gnutls/abstract.h
%{_includedir}/gnutls/compat.h
%{_includedir}/gnutls/crypto.h
%{_includedir}/gnutls/dtls.h
%{_includedir}/gnutls/gnutls.h
%{_includedir}/gnutls/ocsp.h
%{_includedir}/gnutls/openpgp.h
%{_includedir}/gnutls/pkcs11.h
%{_includedir}/gnutls/pkcs12.h
%{_includedir}/gnutls/pkcs7.h
%{_includedir}/gnutls/self-test.h
%{_includedir}/gnutls/socket.h
%{_includedir}/gnutls/system-keys.h
%{_includedir}/gnutls/tpm.h
%{_includedir}/gnutls/urls.h
%{_includedir}/gnutls/x509-ext.h
%{_includedir}/gnutls/x509.h
%{_libdir}/libgnutls-openssl.so
%{_libdir}/libgnutls.so
%{_libdir}/pkgconfig/gnutls.pc

%files -n libgnutlsxx-devel
%dir %{_includedir}/gnutls
%{_includedir}/gnutls/gnutlsxx.h
%{_libdir}/libgnutlsxx.so

%files -n libgnutls-openssl-devel
%dir %{_includedir}/gnutls
%{_includedir}/gnutls/openssl.h
%{_libdir}/libgnutls-openssl.so

%files -n libgnutls-dane-devel
%dir %{_includedir}/gnutls
%{_includedir}/gnutls/dane.h
%{_libdir}/libgnutls-dane.so
%{_libdir}/pkgconfig/gnutls-dane.pc
%endif

%if !(0%{?suse_version} > 1500) && !(0%{?sle_version} > 150000)
%package -n gnutls-c++
Summary: GNU TLS library - C++ runtime library

%description -n gnutls-c++
This package contains the C++ runtime libraries.

%package -n gnutls-openssl
Summary: GNU TLS library - openSSL security support

%description -n gnutls-openssl
This package contains the runtime library of the GnuTLS OpenSSL wrapper.

%package -n gnutls-dane
Summary: GNU TLS library - DANE security support

%description -n gnutls-dane
This package contains the runtime library for DANE (DNS-based
Authentication of Named Entities) support.

%package -n gnutls-devel
Summary: GNU TLS library - development files
Requires: gnutls = %{epoch}:%{version}-%{release}
Requires: gnutls-c++ = %{epoch}:%{version}-%{release}
Requires: gnutls-dane = %{epoch}:%{version}-%{release}
Requires: gnutls-openssl = %{epoch}:%{version}-%{release}
Requires: pkgconfig

%description -n gnutls-devel
This package contains the GnuTLS development files.

%package -n gnutls-utils
Summary: GNU TLS library - commandline utilities
Requires: gnutls = %{epoch}:%{version}-%{release}
Requires: gnutls-c++ = %{epoch}:%{version}-%{release}
Requires: gnutls-dane = %{epoch}:%{version}-%{release}
Requires: gnutls-openssl = %{epoch}:%{version}-%{release}

%description -n gnutls-utils
This package contains a commandline interface to the GNU TLS library,
which can be used to set up secure connections from e.g. shell scripts,
debugging connection issues or managing certificates.

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%post -n gnutls-c++ -p /sbin/ldconfig
%postun -n gnutls-c++ -p /sbin/ldconfig

%post -n gnutls-openssl -p /sbin/ldconfig
%postun -n gnutls-openssl -p /sbin/ldconfig

%post -n gnutls-dane -p /sbin/ldconfig
%postun -n gnutls-dane -p /sbin/ldconfig

%files
%license LICENSE
%{_libdir}/libgnutls.so.*

%files -n gnutls-c++
%{_libdir}/libgnutlsxx.so.*

%files -n gnutls-openssl
%{_libdir}/libgnutls-openssl.so.*

%files -n gnutls-dane
%{_libdir}/libgnutls-dane.so.*

%files -n gnutls-devel
%{_includedir}/*
%{_libdir}/libgnutls*.so
%{_libdir}/pkgconfig/gnutls-dane.pc
%{_libdir}/pkgconfig/gnutls.pc

%files -n gnutls-utils
%{_bindir}/*
%endif

%changelog
