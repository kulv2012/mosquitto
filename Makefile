include config.mk

DIRS=lib client src

.PHONY : all mosquitto binary clean reallyclean test install uninstall sign copy

all : mosquitto

binary : mosquitto

mosquitto :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d}; done

clean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} clean; done
	$(MAKE) -C test clean

reallyclean : 
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} reallyclean; done
	$(MAKE) -C test reallyclean
	-rm -f *.orig

test : mosquitto
	$(MAKE) -C test test

install : mosquitto
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} install; done
	$(INSTALL) -d ${DESTDIR}${prefix}/conf/
	$(INSTALL) -m 644 conf/* ${DESTDIR}${prefix}/conf/

uninstall :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} uninstall; done

dist : reallyclean
	
	mkdir -p dist/mosquitto-${VERSION}
	cp -r client examples installer lib logo man misc security service src test ChangeLog.txt CMakeLists.txt LICENSE.txt LICENSE-3rd-party.txt Makefile compiling.txt config.mk readme.txt readme-windows.txt mosquitto.conf aclfile.example pwfile.example dist/mosquitto-${VERSION}/
	cd dist; tar -zcf mosquitto-${VERSION}.tar.gz mosquitto-${VERSION}/
	set -e; for m in man/*.xml; \
		do \
		hfile=$$(echo $${m} | sed -e 's#man/\(.*\)\.xml#\1#' | sed -e 's/\./-/g'); \
		$(XSLTPROC) $(DB_HTML_XSL) $${m} > dist/$${hfile}.html; \
	done


sign : dist
	cd dist; gpg --detach-sign -a mosquitto-${VERSION}.tar.gz

copy : sign
	cd dist; scp mosquitto-${VERSION}.tar.gz mosquitto-${VERSION}.tar.gz.asc mosquitto:site/mosquitto.org/files/source/
	cd dist; scp *.html mosquitto:site/mosquitto.org/man/
	scp ChangeLog.txt mosquitto:site/mosquitto.org/

