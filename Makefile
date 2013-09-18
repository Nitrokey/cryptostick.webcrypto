HOME?=		/home/roam
FIREFOX_DIR?=	${HOME}/.mozilla/firefox
PROFILE_DIR?=	${FIREFOX_DIR}/1nvbdm1l.default
EXTENSIONS_DIR?=	${PROFILE_DIR}/extensions
XPI_FILE?=	cryptostick.webcrypto@cryptostick.com.xpi

all:
	rm -f "${XPI_FILE}"
	find . -type f \! -path '*/.git/*' \! -name 'Makefile' \! -name '.*.swp' \! -name '*~' \! -name '*.xpi' -print0 | xargs -0r zip "${XPI_FILE}" || (rm -f "${XPI_FILE}"; false)
	cp "${XPI_FILE}" "${EXTENSIONS_DIR}/${XPI_FILE}"

clean:
	rm -f "${XPI_FILE}"


.PHONY:	all clean
