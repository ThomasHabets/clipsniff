# clipsniff/Makefile.am
#
AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = clipsniff
#man_MANS = clipsniff.1
clipsniff_SOURCES = clipsniff.cc

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -f Makefile.in configure autoscan*.log config.guess config.sub
	rm -f ltmain.sh configure.in
doc:
	yodl2man -o clipsniff.1 clipsniff.yodl
