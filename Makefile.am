## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

SUBDIRS = src

EXTRA_DIST = AUTHORS \
             BETATESTING \
             ChangeLog \
             COPYING \
             README \
             README.md \
             conf/* \
             doc/* \
             scripts/*

install-data-hook: installconf

installconf: 
	@echo "Checking chroot storage directory" && \
	if [ ! -d $(localstatedir)/sniffjoke ] ; then \
		echo "Creating chroot storage directory: $(localstatedir)/sniffjoke"; \
		install -d -m 700 $(localstatedir)/sniffjoke; \
	fi; \
	echo "Copying generic location installation" && \
	cp -r conf/generic $(localstatedir)/sniffjoke;
