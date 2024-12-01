EXTRA_DIST =	 derive \
		.cargo/config.toml.in \
		cbindgen.toml \
		dist/rust-bindings.h \
		vendor \
		Cargo.toml Cargo.lock \
		derive/Cargo.toml

### adding all src subdirectories necessary for suricata
EXTRA_DIST += \
	src/applayertemplate \
	src/asn1 \
	src/detect \
	src/ffi \
	src/utils \
	src/x509 \
	src/applayer.rs \
	src/common.rs \
	src/conf.rs \
	src/core.rs \
	src/feature.rs \
	src/filecontainer.rs \
	src/filetracker.rs \
	src/frames.rs \
	src/ja4.rs \
	src/jsonbuilder.rs \
	src/kerberos.rs \
	src/lib.rs \
	src/log.rs \
	src/lua.rs \
	src/lzma.rs \
	src/plugin.rs \
	src/util.rs
				
if ENABLE_BITTORRENT
RUST_FEATURES += bittorrent_dht
endif

if ENABLE_DHCP
RUST_FEATURES += dhcp
endif

if ENABLE_DNS
RUST_FEATURES += dns
endif

if ENABLE_FTP
RUST_FEATURES += ftp
endif

if ENABLE_HTTP
RUST_FEATURES += http2
endif

if ENABLE_KRB5
RUST_FEATURES += krb
endif

if ENABLE_LDAP
RUST_FEATURES += ldap
endif

if ENABLE_SMTP
RUST_FEATURES += smtp
endif

if ENABLE_MQTT
RUST_FEATURES += mqtt
endif

if ENABLE_NTP
RUST_FEATURES += ntp
endif

if ENABLE_RDP
RUST_FEATURES += rdp
endif

if ENABLE_SMB
RUST_FEATURES += smb
endif

if ENABLE_SNMP 
RUST_FEATURES += snmp
endif

if ENABLE_SSH
RUST_FEATURES += ssh
endif

if ENABLE_TELNET
RUST_FEATURES += telnet
endif

if ENABLE_WEBSOCKET
RUST_FEATURES += websocket
endif

# Excluded: dcerpc, enip, ike, modbus, nfs, pgsql, quic, rfb, sip, tftp

if !DEBUG
RELEASE = --release
endif

if RUST_BUILD_STD
NIGHTLY_ARGS = -Z build-std
endif

if ENABLE_TLS
if HAVE_JA3
RUST_FEATURES +=	ja3
endif

if HAVE_JA4
RUST_FEATURES +=	ja4
endif
endif

if DEBUG
RUST_FEATURES +=	debug
endif

if DEBUG_VALIDATION
RUST_FEATURES +=	debug-validate
endif

if RUST_CROSS_COMPILE 
RUST_TARGET = --target $(host_triplet)
endif

all-local: Cargo.toml
if HAVE_CYGPATH
	cd $(abs_top_srcdir)/rust && \
		@rustup_home@ CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(e_rustdir)/target" \
		$(CARGO) build $(RELEASE) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET) -vv
else
	cd $(abs_top_srcdir)/rust && \
		@rustup_home@ CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
		$(CARGO) clean && $(CARGO) fetch && 
		$(CARGO) build $(RELEASE) $(NIGHTLY_ARGS) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET) 
endif
	if test -e $(RUST_SURICATA_LIBDIR)/suricata.lib; then \
		cp -a $(RUST_SURICATA_LIBDIR)/suricata.lib \
			$(RUST_SURICATA_LIBDIR)/${RUST_SURICATA_LIBNAME}; \
	fi
	if test -e $(RUST_SURICATA_LIBDIR)/libsuricata.a; then \
		cp -a $(RUST_SURICATA_LIBDIR)/libsuricata.a \
			$(RUST_SURICATA_LIBDIR)/${RUST_SURICATA_LIBNAME}; \
	fi
	$(MAKE) gen/rust-bindings.h
	mkdir -p $(abs_top_builddir)/rust/gen
	cp -an $(RUST_SURICATA_LIBDIR)/build/suricata-lua-sys-*/out/lua/*.h \
		$(abs_top_builddir)/rust/gen/

install-library:
	$(MKDIR_P) "$(DESTDIR)$(libdir)"
	$(INSTALL_DATA) $(RUST_SURICATA_LIB) "$(DESTDIR)$(libdir)"

uninstall-local:
	rm -f "$(DESTDIR)$(libdir)/$(RUST_SURICATA_LIBNAME)"

clean-local:
	rm -rf target gen

distclean-local:
	rm -rf vendor dist

check:
	cd $(abs_top_srcdir)/rust && \
		CARGO_HOME="$(CARGO_HOME)" @rustup_home@ \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
		$(CARGO) test --all $(RELEASE) --features "$(RUST_FEATURES)"

vendor:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ $(CARGO) vendor

if HAVE_CBINDGEN
gen/rust-bindings.h: $(RUST_SURICATA_LIB)
	PATH=$(CARGO_HOME)/bin:$(PATH) \
	cd $(abs_top_srcdir)/rust &&  \
		cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --verify --output $(abs_top_builddir)/rust/gen/rust-bindings.h || true
else
gen/rust-bindings.h:
endif

doc:
	CARGO_HOME=$(CARGO_HOME) $(CARGO) doc --all-features --no-deps

if HAVE_CBINDGEN
dist/rust-bindings.h:
	PATH=$(CARGO_HOME)/bin:$(PATH) \
	cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/dist/rust-bindings.h
else
dist/rust-bindings.h:
endif

Cargo.toml: Cargo.toml.in

update-lock: Cargo.toml
	cargo update
	mv Cargo.lock Cargo.lock.in
