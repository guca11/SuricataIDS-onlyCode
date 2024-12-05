bin_PROGRAMS = suricata
if BUILD_FUZZTARGETS
    bin_PROGRAMS += fuzz_applayerprotodetectgetproto \
    fuzz_applayerparserparse fuzz_siginit \
    fuzz_confyamlloadstring fuzz_decodepcapfile \
    fuzz_sigpcap fuzz_mimedecparseline fuzz_decodebase64
if HAS_FUZZPCAP
    bin_PROGRAMS += fuzz_sigpcap_aware fuzz_predefpcap_aware
endif
endif

noinst_HEADERS = \
	action-globals.h \
	alert-debuglog.h \
	alert-fastlog.h \
	alert-syslog.h \
	app-layer-detect-proto.h \
	app-layer-events.h \
	app-layer-expectation.h \
	app-layer-frames.h \
	app-layer.h \
	app-layer-parser.h \
	app-layer-protos.h \
	app-layer-register.h \
	build-info.h \
	conf.h \
	conf-yaml-loader.h \
	counters.h \
	datasets.h \
	datasets-ipv4.h \
	datasets-md5.h \
	datasets-reputation.h \
	datasets-sha256.h \
	datasets-string.h \
	decode-events.h \
	decode.h \
	decode-icmpv4.h \
	decode-ipv4.h \
	defrag-config.h \
	defrag.h \
	defrag-hash.h \
	defrag-stack.h \
	defrag-timeout.h \
	detect-app-layer-event.h \
	detect-app-layer-protocol.h \
	detect-asn1.h \
	detect-base64-data.h \
	detect-base64-decode.h \
	detect-bsize.h \
	detect-bypass.h \
	detect-byte-extract.h \
	detect-byte.h \
	detect-bytejump.h \
	detect-bytemath.h \
	detect-bytetest.h \
	detect-classtype.h \
	detect-config.h \
	detect-content.h \
	detect-csum.h \
	detect-datarep.h \
	detect-dataset.h \
	detect-depth.h \
	detect-detection-filter.h \
	detect-distance.h \
	detect-dsize.h \
	detect-engine-address.h \
	detect-engine-address-ipv4.h \
	detect-engine-alert.h \
	detect-engine-analyzer.h \
	detect-engine-build.h \
	detect-engine-content-inspection.h \
	detect-engine-event.h \
	detect-engine-file.h \
	detect-engine-frame.h \
	detect-engine.h \
	detect-engine-helper.h \
	detect-engine-iponly.h \
	detect-engine-loader.h \
	detect-engine-mpm.h \
	detect-engine-payload.h \
	detect-engine-port.h \
	detect-engine-prefilter-common.h \
	detect-engine-prefilter.h \
	detect-engine-profile.h \
	detect-engine-proto.h \
	detect-engine-register.h \
	detect-engine-siggroup.h \
	detect-engine-sigorder.h \
	detect-engine-state.h \
	detect-engine-tag.h \
	detect-engine-threshold.h \
	detect-engine-uint.h \
	detect-fast-pattern.h \
	detect-file-data.h \
	detect-file-hash-common.h \
	detect-filemagic.h \
	detect-filemd5.h \
	detect-filename.h \
	detect-filesha1.h \
	detect-filesha256.h \
	detect-filesize.h \
	detect-filestore.h \
	detect-flowbits.h \
	detect-flow.h \
	detect-flow-age.h \
	detect-flow-pkts.h \
	detect-flowint.h \
	detect-flowvar.h \
	detect-fragbits.h \
	detect-fragoffset.h \
	detect-frame.h \
	detect-geoip.h \
	detect-gid.h \
	detect.h \
	detect-hostbits.h \
	detect-icmp-id.h \
	detect-icmp-seq.h \
	detect-icmpv4hdr.h \
	detect-icode.h \
	detect-id.h \
	detect-ipaddr.h \
	detect-ipopts.h \
	detect-ipproto.h \
	detect-iprep.h \
	detect-ipv4hdr.h \
	detect-isdataat.h \
	detect-itype.h \
	detect-l3proto.h \
	detect-lua-extensions.h \
	detect-lua.h \
	detect-mark.h \
	detect-metadata.h \
	detect-msg.h \
	detect-noalert.h \
	detect-nocase.h \
	detect-offset.h \
	detect-parse.h \
	detect-pcre.h \
	detect-pkt-data.h \
	detect-pktvar.h \
	detect-prefilter.h \
	detect-priority.h \
	detect-rawbytes.h \
	detect-reference.h \
	detect-replace.h \
	detect-requires.h \
	detect-rev.h \
	detect-rpc.h \
	detect-sameip.h \
	detect-sid.h \
	detect-stream_size.h \
	detect-tag.h \
	detect-target.h \
	detect-threshold.h \
	detect-tos.h \
	detect-transform-base64.h \
	detect-transform-casechange.h \
	detect-transform-compress-whitespace.h \
	detect-transform-dotprefix.h \
	detect-transform-header-lowercase.h \
	detect-transform-md5.h \
	detect-transform-pcrexform.h \
	detect-transform-sha1.h \
	detect-transform-sha256.h \
	detect-transform-strip-pseudo-headers.h \
	detect-transform-strip-whitespace.h \
	detect-transform-urldecode.h \
	detect-transform-xor.h \
	detect-ttl.h \
	detect-uricontent.h \
	detect-urilen.h \
	detect-within.h \
	detect-xbits.h \
	device-storage.h \
	feature.h \
	flow-bit.h \
	flow-bypass.h \
	flow.h \
	flow-hash.h \
	flow-manager.h \
	flow-private.h \
	flow-queue.h \
	flow-spare-pool.h \
	flow-storage.h \
	flow-timeout.h \
	flow-util.h \
	flow-var.h \
	flow-worker.h \
	host-bit.h \
	host.h \
	host-queue.h \
	host-storage.h \
	host-timeout.h \
	ippair-bit.h \
	ippair.h \
	ippair-queue.h \
	ippair-storage.h \
	ippair-timeout.h \
	log-cf-common.h \
	log-pcap.h \
	log-stats.h \
	output-eve.h \
	output-eve-stream.h \
	output-eve-null.h \
	output-filedata.h \
	output-file.h \
	output-filestore.h \
	output-flow.h \
	output.h \
	output-json-alert.h \
	output-json-anomaly.h \
	output-json-drop.h \
	output-json-email-common.h \
	output-json-file.h \
	output-json-flow.h \
	output-json-frame.h \
	output-json.h \
	output-json-metadata.h \
	output-json-netflow.h \
	output-json-stats.h \
	output-eve-syslog.h \
	output-lua.h \
	output-packet.h \
	output-stats.h \
	output-streaming.h \
	output-tx.h \
	packet.h \
	packet-queue.h \
	pkt-var.h \
	queue.h \
	reputation.h \
	respond-reject.h \
	respond-reject-libnet11.h \
	runmode-af-packet.h \
	runmode-af-xdp.h \
	runmode-dpdk.h \
	runmode-erf-dag.h \
	runmode-erf-file.h \
	runmode-ipfw.h \
	runmode-napatech.h \
	runmode-netmap.h \
	runmode-nflog.h \
	runmode-nfq.h \
	runmode-pcap-file.h \
	runmode-pcap.h \
	runmodes.h \
	runmode-unittests.h \
	runmode-unix-socket.h \
	runmode-windivert.h \
	rust-context.h \
	rust.h \
	source-af-packet.h \
	source-af-xdp.h \
	source-dpdk.h \
	source-erf-dag.h \
	source-erf-file.h \
	source-ipfw.h \
	source-napatech.h \
	source-netmap.h \
	source-nflog.h \
	source-nfq.h \
	source-nfq-prototypes.h \
	source-pcap-file-directory-helper.h \
	source-pcap-file.h \
	source-pcap-file-helper.h \
	source-pcap.h \
	source-windivert.h \
	source-windivert-prototypes.h \
	stream.h \
	suricata-common.h \
	suricata.h \
	suricata-plugin.h \
	threads-debug.h \
	threads.h \
	threads-profile.h \
	threadvars.h \
	tm-modules.h \
	tmqh-flow.h \
	tmqh-packetpool.h \
	tmqh-simple.h \
	tm-queuehandlers.h \
	tm-queues.h \
	tm-threads-common.h \
	tm-threads.h \
	tree.h \
	interval-tree.h \
	unix-manager.h \
	util-action.h \
	util-affinity.h \
	util-atomic.h \
	util-bpf.h \
	util-buffer.h \
	util-byte.h \
	util-checksum.h \
	util-cidr.h \
	util-classification-config.h \
	util-clock.h \
	util-conf.h \
	util-config.h \
	util-coredump-config.h \
	util-cpu.h \
	util-daemon.h \
	util-datalink.h \
	util-debug-filters.h \
	util-debug.h \
	util-detect.h \
	util-device.h \
	util-dpdk.h \
	util-dpdk-i40e.h \
	util-dpdk-ice.h \
	util-dpdk-ixgbe.h \
	util-dpdk-bonding.h \
	util-ebpf.h \
	util-enum.h \
	util-error.h \
	util-exception-policy.h \
	util-exception-policy-types.h \
	util-file-decompression.h \
	util-file.h \
	util-file-swf-decompression.h \
	util-fix_checksum.h \
	util-fmemopen.h \
	util-hash.h \
	util-hashlist.h \
	util-hash-lookup3.h \
	util-hash-string.h \
	util-host-info.h \
	util-host-os-info.h \
	util-hugepages.h \
	util-hyperscan.h \
	util-ioctl.h \
	util-ip.h \
	util-landlock.h \
	util-logopenfile.h \
	util-log-redis.h \
	util-lua-common.h \
	util-lua.h \
	util-lua-sandbox.h \
	util-macset.h \
	util-magic.h \
	util-memcmp.h \
	util-memcpy.h \
	util-mem.h \
	util-memrchr.h \
	util-misc.h \
	util-mpm-ac.h \
	util-mpm-ac-ks.h \
	util-mpm.h \
	util-mpm-hs.h \
	util-napatech.h \
	util-optimize.h \
	util-pages.h \
	util-path.h \
	util-pidfile.h \
	util-plugin.h \
	util-pool.h \
	util-pool-thread.h \
	util-prefilter.h \
	util-print.h \
	util-privs.h \
	util-profiling.h \
	util-profiling-locks.h \
	util-proto-name.h \
	util-radix-tree.h \
	util-random.h \
	util-reference-config.h \
	util-rohash.h \
	util-rule-vars.h \
	util-runmodes.h \
	util-running-modes.h \
	util-signal.h \
	util-spm-bm.h \
	util-spm-bs2bm.h \
	util-spm-bs.h \
	util-spm.h \
	util-spm-hs.h \
	util-storage.h \
	util-streaming-buffer.h \
	util-syslog.h \
	util-sysfs.h \
	util-systemd.h \
	util-thash.h \
	util-threshold-config.h \
	util-time.h \
	util-unittest.h \
	util-unittest-helper.h \
	util-validate.h \
	util-var.h \
	util-var-name.h \
	util-port-interval-tree.h \
	win32-misc.h \
	win32-service.h \
	win32-syscall.h \
	win32-syslog.h

if ENABLE_ESP
noinst_HEADERS += decode-esp.h
endif

if ENABLE_MQTT
noinst_HEADERS += output-json-mqtt.h
endif

if ENABLE_RAW
noinst_HEADERS += decode-raw.h 
endif	

if ENABLE_SMTP
noinst_HEADERS += app-layer-smtp.h 
noinst_HEADERS += output-json-smtp.h 
noinst_HEADERS += util-lua-smtp.h
endif
	
if ENABLE_IMAP
noinst_HEADERS += app-layer-imap.h
endif	

if ENABLE_KRB5
noinst_HEADERS += detect-krb5-cname.h
noinst_HEADERS += detect-krb5-errcode.h
noinst_HEADERS += detect-krb5-msgtype.h
noinst_HEADERS += detect-krb5-sname.h
noinst_HEADERS += detect-krb5-ticket-encryption.h
endif

if ENABLE_SMB
noinst_HEADERS += app-layer-smb.h
noinst_HEADERS += detect-smb-ntlmssp.h
noinst_HEADERS += detect-smb-share.h
noinst_HEADERS += detect-smb-version.h
noinst_HEADERS += output-json-smb.h
endif

if ENABLE_FTP
noinst_HEADERS += app-layer-ftp.h
noinst_HEADERS += detect-ftpbounce.h
noinst_HEADERS += detect-ftpdata.h
noinst_HEADERS += output-json-ftp.h
endif

if ENABLE_SSH
noinst_HEADERS += app-layer-ssh.h 
noinst_HEADERS += detect-ssh-hassh.h 
noinst_HEADERS += detect-ssh-hassh-server.h 
noinst_HEADERS += detect-ssh-hassh-server-string.h 
noinst_HEADERS += detect-ssh-hassh-string.h 
noinst_HEADERS += detect-ssh-proto.h 
noinst_HEADERS += detect-ssh-proto-version.h 
noinst_HEADERS += detect-ssh-software.h 
noinst_HEADERS += detect-ssh-software-version.h 
noinst_HEADERS += util-lua-ssh.h 
noinst_HEADERS += util-lua-hassh.h 
endif

if ENABLE_ARP
noinst_HEADERS += decode-arp.h 
noinst_HEADERS += output-json-arp.h 
endif

if ENABLE_PPPOE
noinst_HEADERS += decode-pppoe.h 
endif

if ENABLE_DHCP
noinst_HEADERS += output-json-dhcp.h
endif

if ENABLE_DNS
noinst_HEADERS += detect-dns-answer-name.h
noinst_HEADERS += detect-dns-opcode.h
noinst_HEADERS += detect-dns-rcode.h
noinst_HEADERS += detect-dns-rrtype.h
noinst_HEADERS += detect-dns-query.h
noinst_HEADERS += detect-dns-query-name.h
noinst_HEADERS += output-json-dns.h
noinst_HEADERS += util-lua-dns.h
endif

if ENABLE_TLS
noinst_HEADERS += detect-tls-alpn.h 
noinst_HEADERS += detect-tls-cert-fingerprint.h 
noinst_HEADERS += detect-tls-cert-issuer.h 
noinst_HEADERS += detect-tls-cert-serial.h 
noinst_HEADERS += detect-tls-certs.h 
noinst_HEADERS += detect-tls-cert-subject.h 
noinst_HEADERS += detect-tls-cert-validity.h 
noinst_HEADERS += detect-tls-subjectaltname.h 
noinst_HEADERS += detect-tls.h 
noinst_HEADERS += detect-tls-ja3-hash.h 
noinst_HEADERS += detect-tls-ja3s-hash.h 
noinst_HEADERS += detect-tls-ja3s-string.h 
noinst_HEADERS += detect-tls-ja3-string.h 
noinst_HEADERS += detect-tls-sni.h 
noinst_HEADERS += detect-tls-version.h 
noinst_HEADERS += detect-tls-random.h 
noinst_HEADERS += log-tlslog.h 
noinst_HEADERS += log-tlsstore.h 
noinst_HEADERS += output-json-tls.h 
noinst_HEADERS += util-lua-tls.h 
noinst_HEADERS += app-layer-ssl.h 
noinst_HEADERS += detect-ssl-state.h 
noinst_HEADERS += detect-ssl-version.h 
noinst_HEADERS += util-ja3.h
noinst_HEADERS += util-lua-ja3.h
noinst_HEADERS += detect-ja4-hash.h
noinst_HEADERS += util-ja4.h
endif

if ENABLE_HTTP
noinst_HEADERS += app-layer-htp-body.h 
noinst_HEADERS += app-layer-htp-file.h 
noinst_HEADERS += app-layer-htp.h 
noinst_HEADERS += app-layer-htp-libhtp.h 
noinst_HEADERS += app-layer-htp-mem.h 
noinst_HEADERS += app-layer-htp-range.h 
noinst_HEADERS += app-layer-htp-xff.h 
noinst_HEADERS += app-layer-http2.h
noinst_HEADERS += detect-http2.h 
noinst_HEADERS += detect-http-accept-enc.h 
noinst_HEADERS += detect-http-accept.h 
noinst_HEADERS += detect-http-accept-lang.h 
noinst_HEADERS += detect-http-client-body.h
noinst_HEADERS += detect-http-connection.h 
noinst_HEADERS += detect-http-content-len.h 
noinst_HEADERS += detect-http-content-type.h 
noinst_HEADERS += detect-http-cookie.h 
noinst_HEADERS += detect-http-header-common.h 
noinst_HEADERS += detect-http-header.h 
noinst_HEADERS += detect-http-header-names.h 
noinst_HEADERS += detect-http-headers.h 
noinst_HEADERS += detect-http-headers-stub.h 
noinst_HEADERS += detect-http-host.h 
noinst_HEADERS += detect-http-location.h 
noinst_HEADERS += detect-http-method.h 
noinst_HEADERS += detect-http-protocol.h 
noinst_HEADERS += detect-http-raw-header.h 
noinst_HEADERS += detect-http-referer.h 
noinst_HEADERS += detect-http-request-line.h 
noinst_HEADERS += detect-http-response-line.h 
noinst_HEADERS += detect-http-server-body.h 
noinst_HEADERS += detect-http-server.h 
noinst_HEADERS += detect-http-start.h 
noinst_HEADERS += detect-http-stat-code.h 
noinst_HEADERS += detect-http-stat-msg.h 
noinst_HEADERS += detect-http-ua.h 
noinst_HEADERS += detect-http-uri.h 
noinst_HEADERS += log-httplog.h 
noinst_HEADERS += output-json-http.h 
noinst_HEADERS += util-lua-http.h 
endif

#	ETHERNET
noinst_HEADERS += decode-ethernet.h

if ENABLE_UDP
noinst_HEADERS += detect-udphdr.h
endif
noinst_HEADERS += decode-udp.h

if ENABLE_TCP
noinst_HEADERS += detect-tcp-ack.h
noinst_HEADERS += detect-tcphdr.h
noinst_HEADERS += detect-tcpmss.h 
noinst_HEADERS += detect-tcp-seq.h 
noinst_HEADERS += detect-tcp-window.h 
noinst_HEADERS += log-tcp-data.h 
endif
noinst_HEADERS += decode-tcp.h
noinst_HEADERS += detect-tcp-flags.h
noinst_HEADERS += stream-tcp.h 
noinst_HEADERS += stream-tcp-cache.h 
noinst_HEADERS += stream-tcp-inline.h 
noinst_HEADERS += stream-tcp-list.h 
noinst_HEADERS += stream-tcp-private.h 
noinst_HEADERS += stream-tcp-reassemble.h 
noinst_HEADERS += stream-tcp-sack.h 
noinst_HEADERS += stream-tcp-util.h 

if ENABLE_IPV6
noinst_HEADERS += datasets-ipv6.h 
noinst_HEADERS += decode-ipv6.h 
noinst_HEADERS += detect-ipv6hdr.h 
noinst_HEADERS += decode-icmpv6.h 
noinst_HEADERS += detect-icmpv6hdr.h 
noinst_HEADERS += detect-icmpv6-mtu.h 
noinst_HEADERS += detect-engine-address-ipv6.h 
endif

if ENABLE_IKE
noinst_HEADERS += app-layer-ike.h 
noinst_HEADERS += detect-ike-exch-type.h 
noinst_HEADERS += detect-ike-spi.h 
noinst_HEADERS += detect-ike-vendor.h 
noinst_HEADERS += detect-ike-chosen-sa.h 
noinst_HEADERS += detect-ike-key-exchange-payload-length.h 
noinst_HEADERS += detect-ike-nonce-payload-length.h 
noinst_HEADERS += detect-ike-nonce-payload.h 
noinst_HEADERS += detect-ike-key-exchange-payload.h 
noinst_HEADERS += output-json-ike.h 
endif

if ENABLE_SCTP
noinst_HEADERS += decode-sctp.h
endif

if ENABLE_GRE
noinst_HEADERS += decode-gre.h
endif

if ENABLE_PPP
noinst_HEADERS += decode-ppp.h
endif

if ENABLE_SLL
noinst_HEADERS += decode-sll.h
endif

if ENABLE_VXLAN
noinst_HEADERS += decode-vxlan.h
endif

if ENABLE_ERSPAN
noinst_HEADERS += decode-erspan.h 
endif

if ENABLE_MPLS
noinst_HEADERS += decode-mpls.h 
endif

if ENABLE_GENEVE
noinst_HEADERS += decode-geneve.h 
endif

if ENABLE_DCERPC
noinst_HEADERS += output-json-dcerpc.h
noinst_HEADERS += detect-dce-iface.h 
noinst_HEADERS += detect-dce-opnum.h 
noinst_HEADERS += detect-dce-stub-data.h 
noinst_HEADERS += detect-engine-dcepayload.h
endif 

if ENABLE_MODBUS
noinst_HEADERS += app-layer-modbus.h 
noinst_HEADERS += detect-modbus.h 
endif

if ENABLE_DNP3
noinst_HEADERS += app-layer-dnp3.h 
noinst_HEADERS += app-layer-dnp3-objects.h 
noinst_HEADERS += detect-dnp3.h 
noinst_HEADERS += output-json-dnp3.h 
noinst_HEADERS += output-json-dnp3-objects.h 
noinst_HEADERS += util-lua-dnp3.h 
noinst_HEADERS += util-lua-dnp3-objects.h 
endif

if ENABLE_NFS
noinst_HEADERS += app-layer-nfs-tcp.h 
noinst_HEADERS += app-layer-nfs-udp.h 
noinst_HEADERS += detect-nfs-procedure.h 
noinst_HEADERS += detect-nfs-version.h 
noinst_HEADERS += output-json-nfs.h 
endif

if ENABLE_TFTP
noinst_HEADERS += app-layer-tftp.h
endif

if ENABLE_SIP
noinst_HEADERS += detect-sip-method.h
noinst_HEADERS += detect-sip-uri.h
endif

if ENABLE_QUIC
noinst_HEADERS += detect-quic-sni.h 
noinst_HEADERS += detect-quic-ua.h 
noinst_HEADERS += detect-quic-version.h 
noinst_HEADERS += detect-quic-cyu-hash.h 
noinst_HEADERS += detect-quic-cyu-string.h
endif

if ENABLE_PGSQL
noinst_HEADERS += output-json-pgsql.h
endif

if ENABLE_VLAN
noinst_HEADERS += decode-vlan.h
endif

if ENABLE_CHDLC
noinst_HEADERS += decode-chdlc.h
endif

if ENABLE_NSH
noinst_HEADERS += decode-nsh.h
endif

if ENABLE_VNTAG
noinst_HEADERS += decode-vntag.h
endif

if ENABLE_TEREDO
noinst_HEADERS += decode-teredo.h
endif

#	TEMPLATE
#	decode-template.h 
#	detect-template2.h 
#	detect-template.h 
#	detect-template-rust-buffer.h 

libsuricata_c_a_SOURCES = \
	alert-debuglog.c \
	alert-fastlog.c \
	alert-syslog.c \
	app-layer.c \
	app-layer-detect-proto.c \
	app-layer-events.c \
	app-layer-expectation.c \
	app-layer-frames.c \
	app-layer-parser.c \
	app-layer-protos.c \
	app-layer-register.c \
	conf.c \
	conf-yaml-loader.c \
	counters.c \
	datasets.c \
	datasets-ipv4.c \
	datasets-md5.c \
	datasets-sha256.c \
	datasets-string.c \
	decode.c \
	decode-events.c \
	decode-icmpv4.c \
	decode-ipv4.c \
	decode-null.c \
	defrag.c \
	defrag-config.c \
	defrag-hash.c \
	defrag-stack.c \
	defrag-timeout.c \
	detect-app-layer-event.c \
	detect-app-layer-protocol.c \
	detect-asn1.c \
	detect-base64-data.c \
	detect-base64-decode.c \
	detect-bsize.c \
	detect-bypass.c \
	detect-byte.c \
	detect-byte-extract.c \
	detect-bytejump.c \
	detect-bytemath.c \
	detect-bytetest.c \
	detect.c \
	detect-classtype.c \
	detect-config.c \
	detect-content.c \
	detect-csum.c \
	detect-datarep.c \
	detect-dataset.c \
	detect-depth.c \
	detect-detection-filter.c \
	detect-distance.c \
	detect-dsize.c \
	detect-engine-address.c \
	detect-engine-address-ipv4.c \
	detect-engine-alert.c \
	detect-engine-analyzer.c \
	detect-engine-build.c \
	detect-engine.c \
	detect-engine-content-inspection.c \
	detect-engine-event.c \
	detect-engine-file.c \
	detect-engine-frame.c \
	detect-engine-helper.c \
	detect-engine-iponly.c \
	detect-engine-loader.c \
	detect-engine-mpm.c \
	detect-engine-payload.c \
	detect-engine-port.c \
	detect-engine-prefilter.c \
	detect-engine-prefilter-common.c \
	detect-engine-profile.c \
	detect-engine-proto.c \
	detect-engine-register.c \
	detect-engine-siggroup.c \
	detect-engine-sigorder.c \
	detect-engine-state.c \
	detect-engine-tag.c \
	detect-engine-threshold.c \
	detect-engine-uint.c \
	detect-fast-pattern.c \
	detect-file-data.c \
	detect-file-hash-common.c \
	detect-filemagic.c \
	detect-filemd5.c \
	detect-filename.c \
	detect-filesha1.c \
	detect-filesha256.c \
	detect-filesize.c \
	detect-filestore.c \
	detect-flowbits.c \
	detect-flow.c \
	detect-flow-age.c \
	detect-flow-pkts.c \
	detect-flowint.c \
	detect-flowvar.c \
	detect-fragbits.c \
	detect-fragoffset.c \
	detect-frame.c \
	detect-geoip.c \
	detect-gid.c \
	detect-hostbits.c \
	detect-icmp-id.c \
	detect-icmp-seq.c \
	detect-icmpv4hdr.c \
	detect-icode.c \
	detect-id.c \
	detect-ipaddr.c \
	detect-ipopts.c \
	detect-ipproto.c \
	detect-iprep.c \
	detect-ipv4hdr.c \
	detect-isdataat.c \
	detect-itype.c \
	detect-l3proto.c \
	detect-lua.c \
	detect-lua-extensions.c \
	detect-mark.c \
	detect-metadata.c \
	detect-msg.c \
	detect-noalert.c \
	detect-nocase.c \
	detect-offset.c \
	detect-parse.c \
	detect-pcre.c \
	detect-pkt-data.c \
	detect-pktvar.c \
	detect-prefilter.c \
	detect-priority.c \
	detect-rawbytes.c \
	detect-reference.c \
	detect-replace.c \
	detect-requires.c \
	detect-rev.c \
	detect-rpc.c \
	detect-sameip.c \
	detect-sid.c \
	detect-stream_size.c \
	detect-tag.c \
	detect-target.c \
	detect-threshold.c \
	detect-tos.c \
	detect-transform-base64.c \
	detect-transform-casechange.c \
	detect-transform-compress-whitespace.c \
	detect-transform-dotprefix.c \
	detect-transform-header-lowercase.c \
	detect-transform-md5.c \
	detect-transform-pcrexform.c \
	detect-transform-sha1.c \
	detect-transform-sha256.c \
	detect-transform-strip-pseudo-headers.c \
	detect-transform-strip-whitespace.c \
	detect-transform-urldecode.c \
	detect-transform-xor.c \
	detect-ttl.c \
	detect-uricontent.c \
	detect-urilen.c \
	detect-within.c \
	detect-xbits.c \
	device-storage.c \
	feature.c \
	flow-bit.c \
	flow-bypass.c \
	flow.c \
	flow-hash.c \
	flow-manager.c \
	flow-queue.c \
	flow-spare-pool.c \
	flow-storage.c \
	flow-timeout.c \
	flow-util.c \
	flow-var.c \
	flow-worker.c \
	host-bit.c \
	host.c \
	host-queue.c \
	host-storage.c \
	host-timeout.c \
	ippair-bit.c \
	ippair.c \
	ippair-queue.c \
	ippair-storage.c \
	ippair-timeout.c \
	log-cf-common.c \
	log-pcap.c \
	log-stats.c \
	output.c \
	output-eve-stream.c \
	output-file.c \
	output-filedata.c \
	output-filestore.c \
	output-flow.c \
	output-json-alert.c \
	output-json-anomaly.c \
	output-json.c \
	output-json-common.c \
	output-json-drop.c \
	output-json-email-common.c \
	output-json-file.c \
	output-json-flow.c \
	output-json-frame.c \
	output-json-metadata.c \
	output-json-netflow.c \
	output-json-stats.c \
	output-eve.c \
	output-eve-syslog.c \
	output-eve-null.c \
	output-lua.c \
	output-packet.c \
	output-stats.c \
	output-streaming.c \
	output-tx.c \
	packet.c \
	packet-queue.c \
	pkt-var.c \
	reputation.c \
	respond-reject.c \
	respond-reject-libnet11.c \
	runmode-af-packet.c \
	runmode-af-xdp.c \
	runmode-dpdk.c \
	runmode-erf-dag.c \
	runmode-erf-file.c \
	runmode-ipfw.c \
	runmode-napatech.c \
	runmode-netmap.c \
	runmode-nflog.c \
	runmode-nfq.c \
	runmode-pcap.c \
	runmode-pcap-file.c \
	runmodes.c \
	runmode-unittests.c \
	runmode-unix-socket.c \
	runmode-windivert.c \
	rust-context.c \
	source-af-packet.c \
	source-af-xdp.c \
	source-dpdk.c \
	source-erf-dag.c \
	source-erf-file.c \
	source-ipfw.c \
	source-napatech.c \
	source-netmap.c \
	source-nflog.c \
	source-nfq.c \
	source-pcap.c \
	source-pcap-file.c \
	source-pcap-file-directory-helper.c \
	source-pcap-file-helper.c \
	source-windivert.c \
	stream.c \
	suricata.c \
	threads.c \
	tm-modules.c \
	tmqh-flow.c \
	tmqh-packetpool.c \
	tmqh-simple.c \
	tm-queuehandlers.c \
	tm-queues.c \
	tm-threads.c \
	unix-manager.c \
	util-action.c \
	util-affinity.c \
	util-atomic.c \
	util-bpf.c \
	util-buffer.c \
	util-byte.c \
	util-checksum.c \
	util-cidr.c \
	util-classification-config.c \
	util-conf.c \
	util-coredump-config.c \
	util-cpu.c \
	util-daemon.c \
	util-datalink.c \
	util-debug.c \
	util-debug-filters.c \
	util-detect.c \
	util-device.c \
	util-dpdk.c \
	util-dpdk-i40e.c \
	util-dpdk-ice.c \
	util-dpdk-ixgbe.c \
	util-dpdk-bonding.c \
	util-ebpf.c \
	util-enum.c \
	util-error.c \
	util-exception-policy.c \
	util-file.c \
	util-file-decompression.c \
	util-file-swf-decompression.c \
	util-fix_checksum.c \
	util-fmemopen.c \
	util-hash.c \
	util-hashlist.c \
	util-hash-lookup3.c \
	util-hash-string.c \
	util-host-info.c \
	util-host-os-info.c \
	util-hugepages.c \
	util-hyperscan.c \
	util-ioctl.c \
	util-ip.c \
	util-landlock.c \
	util-logopenfile.c \
	util-log-redis.c \
	util-lua.c \
	util-lua-common.c \
	util-lua-sandbox.c \
	util-macset.c \
	util-magic.c \
	util-mem.c \
	util-memcmp.c \
	util-memrchr.c \
	util-misc.c \
	util-mpm-ac.c \
	util-mpm-ac-ks.c \
	util-mpm-ac-ks-small.c \
	util-mpm.c \
	util-mpm-hs.c \
	util-napatech.c \
	util-pages.c \
	util-path.c \
	util-pidfile.c \
	util-plugin.c \
	util-pool.c \
	util-pool-thread.c \
	util-prefilter.c \
	util-print.c \
	util-privs.c \
	util-profiling.c \
	util-profiling-keywords.c \
	util-profiling-locks.c \
	util-profiling-prefilter.c \
	util-profiling-rulegroups.c \
	util-profiling-rules.c \
	util-proto-name.c \
	util-radix-tree.c \
	util-random.c \
	util-reference-config.c \
	util-rohash.c \
	util-rule-vars.c \
	util-runmodes.c \
	util-running-modes.c \
	util-signal.c \
	util-spm-bm.c \
	util-spm-bs2bm.c \
	util-spm-bs.c \
	util-spm.c \
	util-spm-hs.c \
	util-storage.c \
	util-streaming-buffer.c \
	util-strlcatu.c \
	util-strlcpyu.c \
	util-strptime.c \
	util-syslog.c \
	util-sysfs.c \
	util-systemd.c \
	util-thash.c \
	util-threshold-config.c \
	util-time.c \
	util-unittest.c \
	util-unittest-helper.c \
	util-var.c \
	util-var-name.c \
	util-port-interval-tree.c \
	win32-misc.c \
	win32-service.c \
	win32-syscall.c
	
if ENABLE_ESP
libsuricata_c_a_SOURCES += decode-esp.c
endif
	
if ENABLE_MQTT
libsuricata_c_a_SOURCES += output-json-mqtt.c
endif	

if ENABLE_RAW
libsuricata_c_a_SOURCES += decode-raw.c
endif

if ENABLE_SMTP	
libsuricata_c_a_SOURCES += app-layer-smtp.c
libsuricata_c_a_SOURCES += output-json-smtp.c 
libsuricata_c_a_SOURCES += util-lua-smtp.c
endif

if ENABLE_IMAP
libsuricata_c_a_SOURCES += app-layer-imap.c
endif	
	
if ENABLE_KRB5
libsuricata_c_a_SOURCES += detect-krb5-cname.c
libsuricata_c_a_SOURCES += detect-krb5-errcode.c
libsuricata_c_a_SOURCES += detect-krb5-msgtype.c
libsuricata_c_a_SOURCES += detect-krb5-sname.c
libsuricata_c_a_SOURCES += detect-krb5-ticket-encryption.c
endif
	
if ENABLE_SMB
libsuricata_c_a_SOURCES += app-layer-smb.c
libsuricata_c_a_SOURCES += detect-smb-ntlmssp.c
libsuricata_c_a_SOURCES += detect-smb-share.c
libsuricata_c_a_SOURCES += detect-smb-version.c
libsuricata_c_a_SOURCES += output-json-smb.c
endif

if ENABLE_FTP
libsuricata_c_a_SOURCES += app-layer-ftp.c
libsuricata_c_a_SOURCES += detect-ftpbounce.c
libsuricata_c_a_SOURCES += detect-ftpdata.c
libsuricata_c_a_SOURCES += output-json-ftp.c
endif

if ENABLE_SSH
libsuricata_c_a_SOURCES += app-layer-ssh.c
libsuricata_c_a_SOURCES += detect-ssh-hassh.c
libsuricata_c_a_SOURCES += detect-ssh-hassh-server.c
libsuricata_c_a_SOURCES += detect-ssh-hassh-server-string.c 
libsuricata_c_a_SOURCES += detect-ssh-hassh-string.c 
libsuricata_c_a_SOURCES += detect-ssh-proto.c
libsuricata_c_a_SOURCES += detect-ssh-proto-version.c 
libsuricata_c_a_SOURCES += detect-ssh-software.c
libsuricata_c_a_SOURCES += detect-ssh-software-version.c 
libsuricata_c_a_SOURCES += util-lua-ssh.c
libsuricata_c_a_SOURCES += util-lua-hassh.c
endif

if ENABLE_ARP
libsuricata_c_a_SOURCES += decode-arp.c
libsuricata_c_a_SOURCES += output-json-arp.c
endif

if ENABLE_PPPOE
libsuricata_c_a_SOURCES += decode-pppoe.c
endif

if ENABLE_DHCP
libsuricata_c_a_SOURCES += output-json-dhcp.c
endif

if ENABLE_DNS
libsuricata_c_a_SOURCES += detect-dns-answer-name.c
libsuricata_c_a_SOURCES += detect-dns-opcode.c
libsuricata_c_a_SOURCES += detect-dns-rcode.c
libsuricata_c_a_SOURCES += detect-dns-rrtype.c
libsuricata_c_a_SOURCES += detect-dns-query.c
libsuricata_c_a_SOURCES += detect-dns-query-name.c
libsuricata_c_a_SOURCES += output-json-dns.c
libsuricata_c_a_SOURCES += util-lua-dns.c
endif

if ENABLE_TLS
libsuricata_c_a_SOURCES += detect-tls-alpn.c
libsuricata_c_a_SOURCES += detect-tls-cert-fingerprint.c
libsuricata_c_a_SOURCES += detect-tls-cert-issuer.c 
libsuricata_c_a_SOURCES += detect-tls-cert-serial.c
libsuricata_c_a_SOURCES += detect-tls-certs.c
libsuricata_c_a_SOURCES += detect-tls-cert-subject.c 
libsuricata_c_a_SOURCES += detect-tls-cert-validity.c 
libsuricata_c_a_SOURCES += detect-tls-subjectaltname.c 
libsuricata_c_a_SOURCES += detect-tls.c
libsuricata_c_a_SOURCES += detect-tls-ja3-hash.c 
libsuricata_c_a_SOURCES += detect-tls-ja3s-hash.c
libsuricata_c_a_SOURCES += detect-tls-ja3s-string.c
libsuricata_c_a_SOURCES += detect-tls-ja3-string.c 
libsuricata_c_a_SOURCES += detect-tls-sni.c 
libsuricata_c_a_SOURCES += detect-tls-version.c 
libsuricata_c_a_SOURCES += detect-tls-random.c
libsuricata_c_a_SOURCES += log-tlslog.c
libsuricata_c_a_SOURCES += log-tlsstore.c
libsuricata_c_a_SOURCES += output-json-tls.c
libsuricata_c_a_SOURCES += util-lua-tls.c
libsuricata_c_a_SOURCES += app-layer-ssl.c
libsuricata_c_a_SOURCES += detect-ssl-state.c
libsuricata_c_a_SOURCES += detect-ssl-version.c
libsuricata_c_a_SOURCES += util-ja3.c
libsuricata_c_a_SOURCES += util-lua-ja3.c
libsuricata_c_a_SOURCES += detect-ja4-hash.c
endif


if ENABLE_HTTP
libsuricata_c_a_SOURCES += app-layer-htp-body.c 
libsuricata_c_a_SOURCES += app-layer-htp-file.c 
libsuricata_c_a_SOURCES += app-layer-htp.c
libsuricata_c_a_SOURCES += app-layer-htp-libhtp.c 
libsuricata_c_a_SOURCES += app-layer-htp-mem.c
libsuricata_c_a_SOURCES += app-layer-htp-range.c 
libsuricata_c_a_SOURCES += app-layer-htp-xff.c 
libsuricata_c_a_SOURCES += app-layer-http2.c
libsuricata_c_a_SOURCES += detect-http2.c
libsuricata_c_a_SOURCES += detect-http-accept-enc.c 
libsuricata_c_a_SOURCES += detect-http-accept.c
libsuricata_c_a_SOURCES += detect-http-accept-lang.c 
libsuricata_c_a_SOURCES += detect-http-client-body.c
libsuricata_c_a_SOURCES += detect-http-connection.c 
libsuricata_c_a_SOURCES += detect-http-content-len.c 
libsuricata_c_a_SOURCES += detect-http-content-type.c 
libsuricata_c_a_SOURCES += detect-http-cookie.c 
libsuricata_c_a_SOURCES += detect-http-header-common.c 
libsuricata_c_a_SOURCES += detect-http-header.c 
libsuricata_c_a_SOURCES += detect-http-header-names.c 
libsuricata_c_a_SOURCES += detect-http-headers.c 
libsuricata_c_a_SOURCES += detect-http-host.c
libsuricata_c_a_SOURCES += detect-http-location.c 
libsuricata_c_a_SOURCES += detect-http-method.c
libsuricata_c_a_SOURCES += detect-http-protocol.c
libsuricata_c_a_SOURCES += detect-http-raw-header.c 
libsuricata_c_a_SOURCES += detect-http-referer.c
libsuricata_c_a_SOURCES += detect-http-request-line.c
libsuricata_c_a_SOURCES += detect-http-response-line.c 
libsuricata_c_a_SOURCES += detect-http-server-body.c 
libsuricata_c_a_SOURCES += detect-http-server.c 
libsuricata_c_a_SOURCES += detect-http-start.c
libsuricata_c_a_SOURCES += detect-http-stat-code.c 
libsuricata_c_a_SOURCES += detect-http-stat-msg.c 
libsuricata_c_a_SOURCES += detect-http-ua.c
libsuricata_c_a_SOURCES += detect-http-uri.c 
libsuricata_c_a_SOURCES += log-httplog.c
libsuricata_c_a_SOURCES += output-json-http.c
libsuricata_c_a_SOURCES += util-lua-http.c
endif

#	ETHERNET
libsuricata_c_a_SOURCES += decode-ethernet.c

libsuricata_c_a_SOURCES += decode-udp.c
if ENABLE_UDP
libsuricata_c_a_SOURCES += detect-udphdr.c
endif

if ENABLE_TCP
libsuricata_c_a_SOURCES += detect-tcp-ack.c
libsuricata_c_a_SOURCES += detect-tcphdr.c
libsuricata_c_a_SOURCES += detect-tcpmss.c
libsuricata_c_a_SOURCES += detect-tcp-seq.c
libsuricata_c_a_SOURCES += detect-tcp-window.c 
libsuricata_c_a_SOURCES += log-tcp-data.c 
endif
libsuricata_c_a_SOURCES += decode-tcp.c
libsuricata_c_a_SOURCES += detect-tcp-flags.c
libsuricata_c_a_SOURCES += stream-tcp.c
libsuricata_c_a_SOURCES += stream-tcp-cache.c
libsuricata_c_a_SOURCES += stream-tcp-inline.c 
libsuricata_c_a_SOURCES += stream-tcp-list.c
libsuricata_c_a_SOURCES += stream-tcp-reassemble.c 
libsuricata_c_a_SOURCES += stream-tcp-sack.c 
libsuricata_c_a_SOURCES += stream-tcp-util.c

if ENABLE_IPV6
libsuricata_c_a_SOURCES += datasets-ipv6.c 
libsuricata_c_a_SOURCES += decode-ipv6.c 
libsuricata_c_a_SOURCES += detect-ipv6hdr.c
libsuricata_c_a_SOURCES += decode-icmpv6.c 
libsuricata_c_a_SOURCES += detect-icmpv6hdr.c 
libsuricata_c_a_SOURCES += detect-icmpv6-mtu.c
libsuricata_c_a_SOURCES += detect-engine-address-ipv6.c
endif

if ENABLE_IKE
libsuricata_c_a_SOURCES += app-layer-ike.c 
libsuricata_c_a_SOURCES += detect-ike-exch-type.c 
libsuricata_c_a_SOURCES += detect-ike-spi.c 
libsuricata_c_a_SOURCES += detect-ike-vendor.c 
libsuricata_c_a_SOURCES += detect-ike-chosen-sa.c 
libsuricata_c_a_SOURCES += detect-ike-key-exchange-payload-length.c 
libsuricata_c_a_SOURCES += detect-ike-nonce-payload-length.c 
libsuricata_c_a_SOURCES += detect-ike-nonce-payload.c 
libsuricata_c_a_SOURCES += detect-ike-key-exchange-payload.c 
libsuricata_c_a_SOURCES += output-json-ike.c 
endif

if ENABLE_SCTP
libsuricata_c_a_SOURCES += decode-sctp.c 
endif

if ENABLE_GRE
libsuricata_c_a_SOURCES += decode-gre.c 
endif

if ENABLE_PPP
libsuricata_c_a_SOURCES += decode-ppp.c
endif

if ENABLE_SLL
libsuricata_c_a_SOURCES += decode-sll.c
endif

if ENABLE_VXLAN
libsuricata_c_a_SOURCES += decode-vxlan.c
endif

if ENABLE_ERSPAN
libsuricata_c_a_SOURCES += decode-erspan.c 
endif

if ENABLE_MPLS
libsuricata_c_a_SOURCES += decode-mpls.c 
endif

if ENABLE_GENEVE
libsuricata_c_a_SOURCES += decode-geneve.c 
endif

if ENABLE_DCERPC
libsuricata_c_a_SOURCES += output-json-dcerpc.c
libsuricata_c_a_SOURCES += detect-dce-iface.c 
libsuricata_c_a_SOURCES += detect-dce-opnum.c
libsuricata_c_a_SOURCES += detect-dce-stub-data.c 
libsuricata_c_a_SOURCES += detect-engine-dcepayload.c
endif

if ENABLE_MODBUS
libsuricata_c_a_SOURCES += app-layer-modbus.c
libsuricata_c_a_SOURCES += detect-modbus.c
endif

if ENABLE_DNP3
libsuricata_c_a_SOURCES += app-layer-dnp3.c 
libsuricata_c_a_SOURCES += app-layer-dnp3-objects.c 
libsuricata_c_a_SOURCES += detect-dnp3.c 
libsuricata_c_a_SOURCES += output-json-dnp3.c 
libsuricata_c_a_SOURCES += output-json-dnp3-objects.c 
libsuricata_c_a_SOURCES += util-lua-dnp3.c 
libsuricata_c_a_SOURCES += util-lua-dnp3-objects.c 
endif

if ENABLE_NFS
libsuricata_c_a_SOURCES += app-layer-nfs-tcp.c 
libsuricata_c_a_SOURCES += app-layer-nfs-udp.c 
libsuricata_c_a_SOURCES += detect-nfs-procedure.c 
libsuricata_c_a_SOURCES += detect-nfs-version.c 
libsuricata_c_a_SOURCES += output-json-nfs.c 
endif

if ENABLE_TFTP
libsuricata_c_a_SOURCES += app-layer-tftp.c
endif

if ENABLE_SIP
libsuricata_c_a_SOURCES += detect-sip-method.h 
libsuricata_c_a_SOURCES += detect-sip-uri.h
endif

if ENABLE_QUIC
libsuricata_c_a_SOURCES += detect-quic-sni.c 
libsuricata_c_a_SOURCES += detect-quic-ua.c 
libsuricata_c_a_SOURCES += detect-quic-version.c 
libsuricata_c_a_SOURCES += detect-quic-cyu-hash.c 
libsuricata_c_a_SOURCES += detect-quic-cyu-string.c
endif

if ENABLE_PGSQL
libsuricata_c_a_SOURCES += output-json-pgsql.c
endif

if ENABLE_VLAN
libsuricata_c_a_SOURCES += decode-vlan.c 
endif

if ENABLE_CHDLC
libsuricata_c_a_SOURCES += decode-chdlc.c
endif

if ENABLE_NSH
libsuricata_c_a_SOURCES += decode-nsh.c
endif

if ENABLE_VNTAG
libsuricata_c_a_SOURCES += decode-vntag.c
endif

if ENABLE_TEREDO
libsuricata_c_a_SOURCES += decode-teredo.c
endif

#	TEMPLATE
#	decode-template.c 
#	detect-template2.c 
#	detect-template.c
#	detect-template-rust-buffer.c


EXTRA_DIST = \
	tests/stream-tcp-inline.c \
	tests/stream-tcp-list.c \
	tests/detect-ipv4hdr.c \
	tests/detect-ipv6hdr.c \
	tests/detect-tcphdr.c \
	tests/detect-udphdr.c \
	tests/reputation.c \
	tests/detect-bsize.c \
	tests/detect-http2.c \
	tests/detect-icmpv6-mtu.c \
	tests/detect-icmpv6hdr.c \
	tests/detect-template.c \
	tests/detect-transform-pcrexform.c \
	tests/detect-transform-xor.c \
	tests/detect-ttl.c \
	tests/source-pcap.c \
	tests/app-layer-htp-file.c \
	tests/detect-engine-alert.c \
	tests/detect-engine-content-inspection.c \
	tests/detect-icmpv4hdr.c \
	tests/detect-parse.c \
	tests/stream-tcp-reassemble.c \
	tests/detect-file-data.c \
	tests/detect-http-client-body.c \
	tests/detect-http-cookie.c \
	tests/detect-http-header.c \
	tests/detect-http-host.c \
	tests/detect-http-method.c \
	tests/detect-http-raw-header.c \
	tests/detect-http-server-body.c \
	tests/detect-http-stat-code.c \
	tests/detect-http-stat-msg.c \
	tests/detect-http-uri.c \
	tests/detect-http-user-agent.c \
	tests/detect-ssl-state.c \
	tests/detect-ssl-version.c \
	tests/detect-template-buffer.c \
	tests/detect-tls-cert-fingerprint.c \
	tests/detect-tls-cert-issuer.c \
	tests/detect-tls-cert-serial.c \
	tests/detect-tls-cert-subject.c \
	tests/detect-tls-cert-validity.c \
	tests/detect-tls-certs.c \
	tests/detect-tls-version.c \
	tests/detect-ipaddr.c \
	tests/detect.c \
	tests/stream-tcp.c \
	tests/output-json-stats.c

install-headers:
	mkdir -p $(DESTDIR)${includedir}/suricata
	for header in $(noinst_HEADERS); do \
		$(INSTALL_DATA) $$header "$(DESTDIR)${includedir}/suricata"; \
	done

# Until we can remove autoconf.h from our headers, we need to to
# provide this for library/plugin users.
	$(INSTALL_DATA) autoconf.h "$(DESTDIR)${includedir}/suricata"

# set the include path found by configure
AM_CPPFLAGS = $(all_includes)

noinst_LIBRARIES = libsuricata_c.a

suricata_SOURCES = main.c

# the library search path.
suricata_LDFLAGS = $(all_libraries) ${SECLDFLAGS}
# rust library depends also on c
if LINKER_SUPPORTS_GROUP
LDADD_GENERIC = "-Wl,--start-group,libsuricata_c.a,$(RUST_SURICATA_LIB),--end-group" $(HTP_LDADD) $(RUST_LDADD)
else
LDADD_GENERIC = libsuricata_c.a $(RUST_SURICATA_LIB) libsuricata_c.a $(RUST_SURICATA_LIB) $(HTP_LDADD) $(RUST_LDADD)
endif
suricata_LDADD = $(LDADD_GENERIC)
suricata_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)

if BUILD_SHARED_LIBRARY
libsuricata.so.$(VERSION): libsuricata_c.a
	$(CC) -shared -o $@ -Wl,-soname,$@ -Wl,--whole-archive \
		libsuricata_c.a \
		$(RUST_SURICATA_LIB) \
		-Wl,--no-whole-archive
libsuricata.so: libsuricata.so.$(VERSION)
else
libsuricata.so:
	@echo "shared library support not enabled"
	@exit 1
endif

if BUILD_SHARED_LIBRARY
install-library: libsuricata.so.$(VERSION)
else
install-library:
endif
	$(MKDIR_P) "$(DESTDIR)$(libdir)"
	$(INSTALL_DATA) libsuricata_c.a "$(DESTDIR)$(libdir)"
if BUILD_SHARED_LIBRARY
	$(INSTALL) libsuricata.so.$(VERSION) "$(DESTDIR)$(libdir)"
	ln -sf libsuricata.so.$(VERSION) "$(DESTDIR)$(libdir)/libsuricata.so"
endif

uninstall-local:
	rm -f "$(DESTDIR)$(libdir)/libsuricata_c.a"
	rm -f "$(DESTDIR)$(libdir)/libsuricata.so"
	rm -f "$(DESTDIR)$(libdir)/libsuricata.$(VERSION)"

if BUILD_FUZZTARGETS

LDFLAGS_FUZZ = $(all_libraries) $(SECLDFLAGS)
LDADD_FUZZ = $(LDADD_GENERIC)

fuzz_applayerprotodetectgetproto_SOURCES = tests/fuzz/fuzz_applayerprotodetectgetproto.c tests/fuzz/confyaml.c
fuzz_applayerprotodetectgetproto_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_applayerprotodetectgetproto_LDADD = $(LDADD_FUZZ)
fuzz_applayerprotodetectgetproto_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_applayerprotodetectgetproto_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_applayerprotodetectgetproto_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_applayerprotodetectgetproto_SOURCES = force-cxx-linking.cxx

fuzz_applayerparserparse_SOURCES = tests/fuzz/fuzz_applayerparserparse.c tests/fuzz/confyaml.c
fuzz_applayerparserparse_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_applayerparserparse_LDADD = $(LDADD_FUZZ)
fuzz_applayerparserparse_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_applayerparserparse_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_applayerparserparse_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_applayerparserparse_SOURCES = force-cxx-linking.cxx

fuzz_siginit_SOURCES = tests/fuzz/fuzz_siginit.c
fuzz_siginit_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_siginit_LDADD = $(LDADD_FUZZ)
fuzz_siginit_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_siginit_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_siginit_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_siginit_SOURCES = force-cxx-linking.cxx

fuzz_confyamlloadstring_SOURCES = tests/fuzz/fuzz_confyamlloadstring.c
fuzz_confyamlloadstring_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_confyamlloadstring_LDADD = $(LDADD_FUZZ)
fuzz_confyamlloadstring_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_confyamlloadstring_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_confyamlloadstring_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_confyamlloadstring_SOURCES = force-cxx-linking.cxx

fuzz_decodepcapfile_SOURCES = tests/fuzz/fuzz_decodepcapfile.c
fuzz_decodepcapfile_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_decodepcapfile_LDADD = $(LDADD_FUZZ)
fuzz_decodepcapfile_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_decodepcapfile_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_decodepcapfile_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_decodepcapfile_SOURCES = force-cxx-linking.cxx

fuzz_sigpcap_SOURCES = tests/fuzz/fuzz_sigpcap.c tests/fuzz/confyaml.c
fuzz_sigpcap_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_sigpcap_LDADD = $(LDADD_FUZZ)
fuzz_sigpcap_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_sigpcap_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_sigpcap_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_sigpcap_SOURCES = force-cxx-linking.cxx

if HAS_FUZZPCAP
fuzz_sigpcap_aware_SOURCES = tests/fuzz/fuzz_sigpcap_aware.c tests/fuzz/confyaml.c
fuzz_sigpcap_aware_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_sigpcap_aware_LDADD = $(LDADD_FUZZ) -lfuzzpcap
fuzz_sigpcap_aware_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_sigpcap_aware_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_sigpcap_aware_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_sigpcap_aware_SOURCES = force-cxx-linking.cxx

fuzz_predefpcap_aware_SOURCES = tests/fuzz/fuzz_predefpcap_aware.c tests/fuzz/confyaml.c
fuzz_predefpcap_aware_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_predefpcap_aware_LDADD = $(LDADD_FUZZ) -lfuzzpcap
fuzz_predefpcap_aware_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_predefpcap_aware_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_predefpcap_aware_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_predefpcap_aware_SOURCES = force-cxx-linking.cxx
endif

fuzz_decodebase64_SOURCES = tests/fuzz/fuzz_decodebase64.c
fuzz_decodebase64_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_decodebase64_LDADD = $(LDADD_FUZZ)
fuzz_decodebase64_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_decodebase64_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_decodebase64_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_decodebase64_SOURCES = force-cxx-linking.cxx

fuzz_mimedecparseline_SOURCES = tests/fuzz/fuzz_mimedecparseline.c
fuzz_mimedecparseline_LDFLAGS = $(LDFLAGS_FUZZ)
fuzz_mimedecparseline_LDADD = $(LDADD_FUZZ)
fuzz_mimedecparseline_DEPENDENCIES = libsuricata_c.a $(RUST_SURICATA_LIB)
if HAS_FUZZLDFLAGS
    fuzz_mimedecparseline_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_mimedecparseline_SOURCES += tests/fuzz/onefile.c
endif
# force usage of CXX for linker
nodist_EXTRA_fuzz_mimedecparseline_SOURCES = force-cxx-linking.cxx
endif

# default CFLAGS
AM_CFLAGS = ${OPTIMIZATION_CFLAGS} ${GCC_CFLAGS} ${CLANG_CFLAGS}            \
    ${SECCFLAGS} ${PCAP_CFLAGS} -DLOCAL_STATE_DIR=\"$(localstatedir)\"      \
    -Wall -Wno-unused-parameter -Wmissing-prototypes -Wmissing-declarations \
    -Wstrict-prototypes -Wwrite-strings -Wbad-function-cast                 \
    -Wformat-security -Wno-format-nonliteral -Wmissing-format-attribute     \
    -funsigned-char

# different flags for different cases
if DEBUG
AM_CFLAGS += -ggdb -O0
endif

AM_LDFLAGS = ${SECLDFLAGS}

if BUILD_UNITTESTS
check-am:
	-mkdir $(top_builddir)/qa/log/
	$(top_builddir)/src/suricata -u -l $(top_builddir)/qa/log/
	-rm -rf $(top_builddir)/qa/log
endif

distclean-local:
	-rm -rf $(top_builddir)/src/build-info.h
