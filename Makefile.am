SUBDIRS =	hacks src

EXTRA_DIST =	AUTHORS \
		ChangeLog \
		COPYING \
		README \
		README-REALLY-NOW \
		conf/* \
		scripts/*

install-data-hook:	installconf

installconf:
	@echo "Creating config dir and copying config files"
	if [ ! -d $(sysconfdir)/sniffjoke ] ; then \
		echo "Creating $(sysconfdir)sniffjoke"; \
		install -d -m 755 $(sysconfdir)/sniffjoke; \
	fi; \
	cp conf/plugins_enabled.txt $(sysconfdir)/sniffjoke;
