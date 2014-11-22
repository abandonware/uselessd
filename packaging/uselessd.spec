Name:           uselessd
Version:        7
Release:        0
# For a breakdown of the licensing, see README
License:        LGPL-2.0+ and MIT and GPL-2.0+
Summary:        A System and Service Manager that uses less
Url:            http://uselessd.darknedgy.net
Group:          Base/Startup
Source0:        https://bitbucket.org/bcsd/uselessd/downloads/%{name}-%{version}.tar.xz
Source1:        uselessd.manifest
BuildRequires:  gperf
BuildRequires:  intltool >= 0.40.0
BuildRequires:  libacl-devel
BuildRequires:  libblkid-devel >= 2.20
BuildRequires:  libcap-devel
BuildRequires:  libkmod-devel >= 14
BuildRequires:  pkgconfig
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  attr-devel

Obsoletes:      SysVinit < 2.86-24
Obsoletes:      sysvinit < 2.86-24
Provides:       SysVinit = 2.86-24
Provides:       sysvinit = 2.86-24
Provides:       /bin/systemctl
Provides:       /sbin/shutdown

%description
uselessd (the useless daemon, or the daemon that uses less...
depending on your viewpoint) is a project to reduce systemd
to a base initd, process supervisor and transactional dependency
system, while minimizing intrusiveness and isolationism.
Basically, it's systemd with the superfluous stuff cut out,
a (relatively) coherent idea of what it wants to be, support for
non-glibc platforms and an approach that aims to minimize
complicated design.

%package -n libuselessd
License:        LGPL-2.0+ and MIT
Summary:        Uselessd libraries
Group:          Base/Startup
Conflicts:      systemd

%description -n libuselessd
Libraries for %{name}.

%package devel
License:        LGPL-2.0+ and MIT
Summary:        Development headers for %{name}
Requires:       %{name} = %{version}

%description devel
Development headers and auxiliary files for developing applications for %{name}.

%package analyze
License:        LGPL-2.0+
Summary:        Tool for processing uselessd profiling information
Requires:       %{name} = %{version}

%description analyze
'systemd-analyze blame' lists which systemd unit needed how much time to finish
initialization at boot.
'systemd-analyze plot' renders an SVG visualizing the parallel start of units
at boot.

%prep
%setup -q
cp %{SOURCE1} .

%build
%reconfigure \
        --libexecdir=%{_prefix}/lib \
        --docdir=%{_docdir}/uselessd \
        --disable-static \
        --with-sysvinit-path= \
        --with-sysvrcnd-path= \
        --with-smack-run-label=System
make %{?_smp_mflags} \
        systemunitdir=%{_unitdir} \
        userunitdir=%{_unitdir_user}

%install
%make_install

# Create SysV compatibility symlinks. systemctl/uselessd are smart
# enough to detect in which way they are called.
/usr/bin/mkdir -p %{buildroot}%{_sbindir}
/usr/bin/ln -s ../lib/systemd/uselessd %{buildroot}%{_sbindir}/init
/usr/bin/ln -s ../lib/systemd/uselessd %{buildroot}%{_bindir}/uselessd
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/reboot
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/halt
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/poweroff
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/shutdown
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/telinit
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/runlevel

# We create all wants links manually at installation time to make sure
# they are not owned and hence overriden by rpm after the used deleted
# them.
/usr/bin/rm -r %{buildroot}%{_sysconfdir}/systemd/system/*.target.wants

# Make sure the ghost-ing below works
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel2.target
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel3.target
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel4.target
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel5.target

# Make sure these directories are properly owned
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/basic.target.wants
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/default.target.wants
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/dbus.target.wants
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/syslog.target.wants

# Make sure the user generators dir exists too
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-generators
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/user-generators

# Create new-style configuration files so that we can ghost-own them
/usr/bin/touch %{buildroot}%{_sysconfdir}/hostname
/usr/bin/touch %{buildroot}%{_sysconfdir}/vconsole.conf
/usr/bin/touch %{buildroot}%{_sysconfdir}/locale.conf
/usr/bin/touch %{buildroot}%{_sysconfdir}/machine-id
/usr/bin/touch %{buildroot}%{_sysconfdir}/machine-info
/usr/bin/touch %{buildroot}%{_sysconfdir}/timezone

/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-preset/
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/user-preset/

# Make sure the shutdown/sleep drop-in dirs exist
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-shutdown/
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-sleep/

# Install modprobe fragment
/usr/bin/mkdir -p %{buildroot}%{_sysconfdir}/modprobe.d/

# Fix the dangling /var/lock -> /run/lock symlink
install -Dm644 tmpfiles.d/legacy.conf %{buildroot}%{_prefix}/lib/tmpfiles.d/legacy.conf

rm -rf %{buildroot}/%{_prefix}/lib/systemd/user/default.target

rm -rf %{buildroot}/%{_docdir}/%{name}

# Move macros to the proper location for Tizen
mkdir -p %{buildroot}%{_sysconfdir}/rpm
install -m644 src/core/macros.systemd %{buildroot}%{_sysconfdir}/rpm/macros.systemd
rm -f %{buildroot}%{_prefix}/lib/rpm/macros.d/macros.systemd

%post
/usr/bin/systemd-machine-id-setup > /dev/null 2>&1 || :
/usr/lib/systemd/systemd-random-seed save > /dev/null 2>&1 || :
/usr/bin/systemctl daemon-reexec > /dev/null 2>&1 || :

%postun
if [ $1 -ge 1 ] ; then
        /usr/bin/systemctl daemon-reload > /dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ] ; then
        /usr/bin/systemctl disable \
                getty@.service \
                remote-fs.target >/dev/null 2>&1 || :

        /usr/bin/rm -f /etc/systemd/system/default.target >/dev/null 2>&1 || :
fi

%post -n libuselessd -p /sbin/ldconfig
%postun -n libuselessd -p /sbin/ldconfig



%files
%manifest %{name}.manifest
%dir %{_prefix}/lib/kernel
%dir %{_prefix}/lib/kernel/install.d
%dir %{_sysconfdir}/systemd
%dir %{_sysconfdir}/systemd/system
%dir %{_sysconfdir}/systemd/user
%dir %{_sysconfdir}/tmpfiles.d
%dir %{_sysconfdir}/sysctl.d
%{_datadir}/bash-completion/*
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/*
%dir %{_prefix}/lib/systemd
%dir %{_prefix}/lib/systemd/system
%dir %{_prefix}/lib/systemd/system-generators
%dir %{_prefix}/lib/systemd/user-generators
%dir %{_prefix}/lib/systemd/system-shutdown
%dir %{_prefix}/lib/systemd/system-sleep
%dir %{_prefix}/lib/tmpfiles.d
%dir %{_prefix}/lib/sysctl.d
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.systemd1.conf
%config(noreplace) %{_sysconfdir}/systemd/system.conf
%config(noreplace) %{_sysconfdir}/systemd/user.conf
%config %{_sysconfdir}/rpm/macros.systemd
%{_sysconfdir}/xdg/systemd
%ghost %config(noreplace) %{_sysconfdir}/hostname
%ghost %config(noreplace) %{_sysconfdir}/vconsole.conf
%ghost %config(noreplace) %{_sysconfdir}/locale.conf
%ghost %config(noreplace) %{_sysconfdir}/machine-id
%ghost %config(noreplace) %{_sysconfdir}/machine-info
%ghost %config(noreplace) %{_sysconfdir}/timezone
%{_bindir}/uselessd
%{_bindir}/uselessd-hostname-setup
%{_bindir}/uselessd-loopback-setup
%{_bindir}/systemctl
%{_bindir}/systemd-notify
%{_bindir}/systemd-ask-password
%{_bindir}/systemd-tty-ask-password-agent
%{_bindir}/systemd-machine-id-setup
%{_bindir}/systemd-tmpfiles
%{_bindir}/systemd-cgtop
%{_bindir}/systemd-delta
%{_prefix}/lib/sysctl.d/*.conf
%{_prefix}/lib/systemd/uselessd
%{_prefix}/lib/systemd/system

%dir /usr/lib/systemd/system/basic.target.wants
%dir %{_prefix}/lib/systemd/user
%{_prefix}/lib/systemd/user/bluetooth.target
%{_prefix}/lib/systemd/user/exit.target
%{_prefix}/lib/systemd/user/printer.target
%{_prefix}/lib/systemd/user/shutdown.target
%{_prefix}/lib/systemd/user/sockets.target
%{_prefix}/lib/systemd/user/sound.target
%{_prefix}/lib/systemd/user/systemd-exit.service
%{_prefix}/lib/systemd/user/paths.target
%{_prefix}/lib/systemd/user/smartcard.target

%{_prefix}/lib/systemd/systemd-*
%{_prefix}/lib/systemd/system-generators/systemd-getty-generator
%{_prefix}/lib/tmpfiles.d/systemd.conf
%{_prefix}/lib/tmpfiles.d/x11.conf
%{_prefix}/lib/tmpfiles.d/tmp.conf
%{_prefix}/lib/tmpfiles.d/legacy.conf
%{_sbindir}/init
%{_sbindir}/reboot
%{_sbindir}/halt
%{_sbindir}/poweroff
%{_sbindir}/shutdown
%{_sbindir}/telinit
%{_sbindir}/runlevel
%{_datadir}/dbus-1/services/org.freedesktop.systemd1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.systemd1.service
%{_datadir}/dbus-1/interfaces/org.freedesktop.systemd1.*.xml
%dir %{_datadir}/polkit-1
%dir %{_datadir}/polkit-1/actions
%{_datadir}/polkit-1/actions/org.freedesktop.systemd1.policy
%{_datadir}/pkgconfig/systemd.pc

# Make sure we don't remove runlevel targets from F14 alpha installs,
# but make sure we don't create then anew.
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel2.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel3.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel4.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel5.target

%files -n libuselessd
%manifest %{name}.manifest
%{_libdir}/libsystemd-daemon.so.*
%{_libdir}/libsystemd-id128.so.*

%files devel
%manifest %{name}.manifest
%{_libdir}/libsystemd-daemon.so
%{_libdir}/libsystemd-id128.so
%dir %{_includedir}/systemd
%{_includedir}/systemd/sd-daemon.h
%{_includedir}/systemd/sd-id128.h
%{_includedir}/systemd/sd-messages.h
%{_includedir}/systemd/sd-shutdown.h
%{_libdir}/pkgconfig/libsystemd-daemon.pc
%{_libdir}/pkgconfig/libsystemd-id128.pc

%files analyze
%manifest %{name}.manifest
%{_bindir}/systemd-analyze

