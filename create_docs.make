ROFFIT = roffit
LIBPCAPDIR = ./wpcap/libpcap
DOCDIR = ./npcap-sdk/docs

PCT = %

%.3pcap: %.3pcap.in
	sed -e 's/@MAN_MISC_INFO@/7/g' -e 's/@MAN_FILE_FORMATS@/5/g' $< > $@
%.7: %.manmisc.in
	sed -e 's/@MAN_MISC_INFO@/7/g' -e 's/@MAN_FILE_FORMATS@/5/g' $< > $@
%.5: %.manfile.in
	sed -e 's/@MAN_MISC_INFO@/7/g' -e 's/@MAN_FILE_FORMATS@/5/g' $< > $@

${DOCDIR}/wpcap/pcap.html: $(LIBPCAPDIR)/pcap.3pcap $(LIBPCAPDIR)/pcap.3pcap $(LIBPCAPDIR)/pcap_compile.3pcap $(LIBPCAPDIR)/pcap_datalink.3pcap $(LIBPCAPDIR)/pcap_dump_open.3pcap $(LIBPCAPDIR)/pcap_get_tstamp_precision.3pcap $(LIBPCAPDIR)/pcap_list_datalinks.3pcap $(LIBPCAPDIR)/pcap_list_tstamp_types.3pcap $(LIBPCAPDIR)/pcap_open_dead.3pcap $(LIBPCAPDIR)/pcap_open_offline.3pcap $(LIBPCAPDIR)/pcap_set_tstamp_precision.3pcap $(LIBPCAPDIR)/pcap_set_tstamp_type.3pcap $(LIBPCAPDIR)/pcap-savefile.5 $(LIBPCAPDIR)/pcap-filter.7 $(LIBPCAPDIR)/pcap-linktype.7 $(LIBPCAPDIR)/pcap-tstamp.7
	mkdir -p ${DOCDIR}/wpcap/ build/wpcap/
	rm -f ${DOCDIR}/wpcap/*.html build/wpcap/*.html
# Generate the contents
	find "$(LIBPCAPDIR)" -maxdepth 1 \( -name '*.3pcap' -o -name '*.7' -o -name '*.5' \) | while read m; do \
		p=$${m$(PCT).3pcap} ; \
		p=$${p$(PCT).7} ; \
		p=$${p$(PCT).5} ; \
		p=$${p##*/} ; \
		$(ROFFIT) --mandir="$(LIBPCAPDIR)" --hrefdir=. "$$m" > ${DOCDIR}/wpcap/$$p.html ; \
	done
