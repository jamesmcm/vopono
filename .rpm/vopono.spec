%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: vopono
Summary: Launch applications via VPN tunnels using temporary network namespaces
Version: @@VERSION@@
Release: @@RELEASE@@%{?dist}
License: GPLv3+
Group: Applications/System
Source0: %{name}-%{version}.tar.gz
URL: https://github.com/jamesmcm/vopono

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
