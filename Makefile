prefix=/usr/local
bindir=$(prefix)/bin
libdir=$(prefix)/lib
mandir=$(prefix)/man
rpmdumpheader=$(bindir)/rpmdumpheader
zlibdir=zlib-1.2.2.f-rsyncable
zlibbundled=$(zlibdir)/libz.a
zlibldflags=$(zlibbundled)
zlibcppflags=-I$(zlibdir)
pylibprefix=/
CFLAGS = -fPIC -O2 -Wall -g
CPPFLAGS = -fPIC -DDELTARPM_64BIT -DBSDIFF_NO_SUF -DRPMDUMPHEADER=\"$(rpmdumpheader)\" $(zlibcppflags)
LDLIBS = -lbz2 $(zlibldflags) -llzma
LDFLAGS =
PYTHONS = python python3

all: makedeltarpm applydeltarpm rpmdumpheader makedeltaiso applydeltaiso combinedeltarpm fragiso

python: _deltarpmmodule.so

makedeltarpm: makedeltarpm.o writedeltarpm.o md5.o util.o rpml.o rpmhead.o cpio.o delta.o cfile.o $(zlibbundled)

applydeltarpm: applydeltarpm.o readdeltarpm.o md5.o sha256.o util.o rpmhead.o cpio.o cfile.o prelink.o $(zlibbundled)

combinedeltarpm: combinedeltarpm.o md5.o util.o rpmhead.o cfile.o readdeltarpm.o writedeltarpm.o $(zlibbundled)

rpmdumpheader: rpmdumpheader.o
	$(CC) $(LDFLAGS) $^ -lrpm -lrpmio -o $@

makedeltaiso: makedeltaiso.o delta.o rpmoffs.o rpmhead.o util.o md5.o cfile.o $(zlibbundled)

applydeltaiso: applydeltaiso.o util.o md5.o cfile.o $(zlibbundled)

fragiso: fragiso.o util.o md5.o rpmhead.o cfile.o $(zlibbundled)

_deltarpmmodule.so: readdeltarpm.o rpmhead.o util.o md5.o cfile.o $(zlibbundled)
	for PY in $(PYTHONS) ; do \
		if [ -x /usr/bin/$$PY-config ] && [ -x /usr/bin/$$PY ]; then \
			PYVER=`$$PY -c 'from distutils import sysconfig ; print(sysconfig.get_python_version())'`; \
			PYCFLAGS=`$$PY-config --cflags`; \
			if [ ! -f "python$$PYVER/$@" ]; then \
				mkdir -p python$$PYVER ;\
				$(CC) $(CFLAGS) $$PYCFLAGS $(zlibcppflags) -fPIC -c -o python$$PYVER/deltarpmmodule.o deltarpmmodule.c ;\
				$(CC) $(LDFLAGS) -o python$$PYVER/$@ python$$PYVER/deltarpmmodule.o $^ -shared -Wl,-soname,_deltarpmmodule.so $(LDLIBS); \
			fi; \
		fi; \
	done

$(zlibbundled):
	cd $(zlibdir) ; make CFLAGS="-fPIC $(CFLAGS)" libz.a

clean:
	rm -f *.o
	rm -f makedeltarpm applydeltarpm combinedeltarpm rpmdumpheader makedeltaiso applydeltaiso fragiso
	cd $(zlibdir) ; make clean

install:
	mkdir -p $(DESTDIR)$(bindir)
	install -m 755 makedeltarpm  $(DESTDIR)$(bindir)
	install -m 755 applydeltarpm $(DESTDIR)$(bindir)
	install -m 755 combinedeltarpm $(DESTDIR)$(bindir)
	install -m 755 rpmdumpheader $(DESTDIR)$(rpmdumpheader)
	install -m 755 makedeltaiso $(DESTDIR)$(bindir)
	install -m 755 applydeltaiso $(DESTDIR)$(bindir)
	install -m 755 fragiso $(DESTDIR)$(bindir)
	install -m 755 drpmsync $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)$(mandir)/man8
	install -m 644 makedeltarpm.8 $(DESTDIR)$(mandir)/man8
	install -m 644 applydeltarpm.8 $(DESTDIR)$(mandir)/man8
	install -m 644 combinedeltarpm.8 $(DESTDIR)$(mandir)/man8
	install -m 644 makedeltaiso.8 $(DESTDIR)$(mandir)/man8
	install -m 644 applydeltaiso.8 $(DESTDIR)$(mandir)/man8
	install -m 644 fragiso.8 $(DESTDIR)$(mandir)/man8
	install -m 644 drpmsync.8 $(DESTDIR)$(mandir)/man8
	for PY in $(PYTHONS) ; do \
		if [ -x /usr/bin/$$PY ]; then \
                        PYLIB=`$$PY -c 'from distutils import sysconfig ; print(sysconfig.get_python_lib(1))'` ; \
			PYVER=`$$PY -c 'from distutils import sysconfig ; print(sysconfig.get_python_version())'` ; \
			if [ -e python$$PYVER/_deltarpmmodule.so ]; then \
				mkdir -p $(DESTDIR)$(pylibprefix)$$PYLIB ; \
				install -m 755 python$$PYVER/_deltarpmmodule.so $(DESTDIR)$(pylibprefix)$$PYLIB ; \
				install -m 644 deltarpm.py $(DESTDIR)$(pylibprefix)$$PYLIB ; \
			fi; \
		fi; \
	done

.PHONY: clean install

makedeltarpm.o: makedeltarpm.c deltarpm.h util.h md5.h rpmhead.h delta.h cfile.h
applydeltarpm.o: applydeltarpm.c deltarpm.h util.h md5.h rpmhead.h cpio.h cfile.h prelink.h
rpmdumpheader.o: rpmdumpheader.c
makedeltaiso.o: makedeltaiso.c delta.h rpmoffs.h cfile.h md5.h
applydeltaiso.o: applydeltaiso.c cfile.h md5.h
combinedeltarpm.o: combinedeltarpm.c cfile.h md5.h rpmhead.h deltarpm.h
md5.o: md5.c md5.h
util.o: util.c util.h
rpml.o: rpml.c rpml.h
cpio.o: cpio.c cpio.h
rpmhead.o: rpmhead.c rpmhead.h
delta.o: delta.c delta.h util.h
prelink.o: prelink.c prelink.h
cfile.o: cfile.c cfile.h
rpmoffs.o: rpmoffs.c rpmoffs.h
readdeltarpm.o: readdeltarpm.c deltarpm.h util.h md5.h rpmhead.h cfile.h
writedeltarpm.o: readdeltarpm.c deltarpm.h md5.h rpmhead.h cfile.h
fragiso.o: fragiso.c util.h md5.h rpmhead.h cfile.h
deltarpmmodule.o: deltarpmmodule.c
