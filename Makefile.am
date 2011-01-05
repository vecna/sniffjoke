## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS =	subdir-objects

SUBDIRS =		src

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
	cp conf/plugins_enabled.conf.generic $(sysconfdir)/sniffjoke; \
	echo "Checking chroot directory" && \
	if [ ! -d $(localstatedir)/sniffjoke ] ; then \
		echo "Creating chroot dir: $(localstatedir)/sniffjoke"; \
		install -d -m 700 $(localstatedir)/sniffjoke; \
	fi;
