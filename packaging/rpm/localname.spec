# Packages a prebuilt binary; build with packaging/build-packages.sh.
Name:           localname
Version:        %{localname_version}
Release:        1
Summary:        Fast, safe, friendly names for local networks
License:        MIT OR Apache-2.0
URL:            https://github.com/NCirit/localname
BuildArch:      %{localname_arch}
Requires:       systemd

%description
localname gives devices on a home network memorable names such as nas.home.arpa:
an authoritative local DNS zone with forwarding, guided router setup, an optional
HTTP/WebSocket proxy, and explicit HTTPS trust modes.

%install
install -Dm0755 %{localname_source}/localname %{buildroot}/usr/bin/localname
install -Dm0644 %{localname_source}/localname.service %{buildroot}/usr/lib/systemd/system/localname.service
install -Dm0644 %{localname_source}/localname.sysusers %{buildroot}/usr/lib/sysusers.d/localname.conf
install -Dm0644 %{localname_source}/localname.tmpfiles %{buildroot}/usr/lib/tmpfiles.d/localname.conf
install -Dm0644 %{localname_source}/README.md %{buildroot}/usr/share/doc/localname/README.md
cp -r %{localname_source}/skills %{buildroot}/usr/share/localname-skills

%files
/usr/bin/localname
/usr/lib/systemd/system/localname.service
/usr/lib/sysusers.d/localname.conf
/usr/lib/tmpfiles.d/localname.conf
/usr/share/doc/localname/README.md
/usr/share/localname-skills

%post
systemd-sysusers localname.conf
systemd-tmpfiles --create localname.conf
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi

%preun
# Erase (not upgrade): stop and disable. Data in /var/lib/localname is kept.
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl disable --now localname.service >/dev/null 2>&1 || true
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # Upgrade: restart a running service on the new binary.
    if [ "$1" -ge 1 ]; then systemctl try-restart localname.service || true; fi
fi
