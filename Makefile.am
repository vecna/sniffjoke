SUBDIRS =		hacks src

EXTRA_DIST =		AUTHORS \
			ChangeLog \
			COPYING \
			README \
			README-REALLY-NOW \
			conf/* \
			scripts/*

install-data-hook:	installconf

installconf:
	@echo "Checking config dir and copying config files" && \
	if [ ! -d $(sysconfdir)/sniffjoke ] ; then \
		echo "Creating config dir: $(sysconfdir)/sniffjoke"; \
		install -d -m 755 $(sysconfdir)/sniffjoke; \
	fi; \
	cp conf/plugins_enabled.conf.default $(sysconfdir)/sniffjoke; \
	echo "Checking chroot directory" && \
	if [ ! -d $(localstatedir)/sniffjoke ] ; then \
		echo "Creating chroot dir: $(localstatedir)/sniffjoke"; \
		install -d -m 700 $(localstatedir)/sniffjoke; \
	fi;
