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
		echo "Creating config dir: $(sysconfdir)sniffjoke"; \
		install -d -m 755 $(sysconfdir)/sniffjoke; \
	fi; \
	cp conf/plugins_enabled.txt $(sysconfdir)/sniffjoke; \
	echo "Checking chroot directory" && \
	if [ ! -d $(localstatedir)/sniffjoke ] ; then \
		echo "Creating chroot dir: $(localstatedir)sniffjoke"; \
		install -d -m 700 $(localstatedir)/sniffjoke; \
	fi;

CLEANFILES =		-R aclocal.m4 \
			autom4te.cache \
			configure \
			config.guess \
			config.log \
			config.status \
			config.sub \
			depcomp \
			install-sh \
			libltdl \
			ltmain.sh \
			missing \
			Makefile \
			Makefile.in
