#!/bin/bash
set -euo pipefail
cd /workspace
umask 022
# Prepare host tools only. Never clone, populate, reset, or change project checkouts.
if ! /usr/bin/python3 - <<'CHECK'
import platform
from pathlib import Path
text=Path('/etc/os-release').read_text()
assert 'ID=debian\n' in text and 'VERSION_ID="13"' in text
assert platform.machine() == 'x86_64'
CHECK
then
    echo 'This setup requires the Debian 13 x86_64 cloud base image.' >&2
    exit 1
fi
for tool in gcc g++ make git perl python3 curl wget pkg-config dpkg dpkg-deb; do
    command -v "$tool" >/dev/null
done
setup_root=/workspace/.openwrt-onboarding
if [ -e "$setup_root" ] && [ ! -f "$setup_root/.managed-setup" ]; then
    echo "Refusing to overwrite an unmanaged setup directory: $setup_root" >&2
    exit 1
fi
mkdir -p "$setup_root/apt/lists/partial" "$setup_root/apt/archives/partial" "$setup_root/apt/log" "$setup_root/apt/conf.d" "$setup_root/host"
printf 'OpenWrt host tools setup; no source checkout management.\n' > "$setup_root/.managed-setup"
# Private APT state avoids administrative access. Use official signed Debian
# repositories over verified HTTPS; leave the machine's APT configuration intact.
cat > "$setup_root/apt/sources.list" <<'SOURCES'
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian trixie main
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian trixie-updates main
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://security.debian.org/debian-security trixie-security main
SOURCES
cat > "$setup_root/apt/apt.conf" <<'APTCONF'
Dir::Etc::parts "/workspace/.openwrt-onboarding/apt/conf.d";
Dir::Etc::sourcelist "/workspace/.openwrt-onboarding/apt/sources.list";
Dir::Etc::sourceparts "-";
Dir::State::lists "/workspace/.openwrt-onboarding/apt/lists";
Dir::State::extended_states "/workspace/.openwrt-onboarding/apt/extended_states";
Dir::Cache::archives "/workspace/.openwrt-onboarding/apt/archives";
Dir::Log "/workspace/.openwrt-onboarding/apt/log";
Debug::NoLocking "true";
APT::Update::Error-Mode "any";
Acquire::Languages "none";
Acquire::https::CaInfo "/etc/ssl/certs/ca-certificates.crt";
APTCONF
export APT_CONFIG="$setup_root/apt/apt.conf"
/usr/bin/apt-get update
/usr/bin/apt-get --download-only --assume-yes --no-install-recommends install \
    build-essential cmake ninja-build bison flex gawk rsync gettext \
    libncurses-dev zlib1g-dev libssl-dev python3-setuptools swig libelf-dev \
    xsltproc ccache autoconf automake libtool libtool-bin libfl-dev libltdl-dev \
    bc gperf time zip unzip
# Include the runtime peers of private development-library symlinks even when
# those runtime packages are already installed in the base image.
/usr/bin/apt-get --download-only --assume-yes --no-install-recommends --reinstall install \
    libelf1t64 libltdl7 libncurses6 libncursesw6 libtinfo6
/usr/bin/python3 - <<'EXTRACT'
import os, subprocess, hashlib
from pathlib import Path
root=Path('/workspace/.openwrt-onboarding')
prefix=root/'host'
selected={}
for archive in sorted((root/'apt/archives').glob('*.deb')):
    fields=subprocess.check_output(['dpkg-deb','-f',str(archive),'Package','Version','Architecture'],text=True)
    metadata=dict(line.split(': ',1) for line in fields.strip().splitlines())
    key=(metadata['Package'],metadata['Architecture'])
    version=metadata['Version']
    if key not in selected or subprocess.run(['dpkg','--compare-versions',version,'gt',selected[key][0]]).returncode == 0:
        selected[key]=(version,archive)
manifest=[]
checksums=[]
for (package,architecture),(version,archive) in sorted(selected.items()):
    subprocess.run(['dpkg-deb','-x',str(archive),str(prefix)],check=True)
    manifest.append(f'{package}\t{version}\t{architecture}')
    checksums.append(f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}')
(root/'packages.txt').write_text('\n'.join(manifest)+'\n')
(root/'package-archives.sha256').write_text('\n'.join(checksums)+'\n')
# Debian alternatives and absolute peer-package symlinks are local setup
# configuration; restore them in this private prefix without system writes.
for name,target in [('automake','automake-1.17'),('aclocal','aclocal-1.17'),('yacc','bison.yacc')]:
    link=prefix/'usr/bin'/name
    if not os.path.lexists(link):link.symlink_to(target)
link=prefix/'usr/share/libtool/m4'
if not os.path.lexists(link):link.symlink_to('../aclocal')
for directory,dirs,files in os.walk(prefix,followlinks=False):
    for name in dirs+files:
        link=Path(directory)/name
        if link.is_symlink():
            target=os.readlink(link)
            relocated=prefix/target.lstrip('/')
            if target.startswith('/') and relocated.exists():
                link.unlink()
                link.symlink_to(os.path.relpath(relocated,link.parent))
source=prefix/'usr/share/autoconf/autom4te.cfg'
(root/'autom4te.cfg').write_text(source.read_text().replace('/usr/share/autoconf',str(prefix/'usr/share/autoconf')))
print(f'Prepared {len(selected)} signed Debian packages in {prefix}')
EXTRACT

/usr/bin/python3 - <<'NATIVE'
from pathlib import Path
root=Path('/workspace/.openwrt-onboarding')
commands=root/'bin'
commands.mkdir(exist_ok=True)
for name in ['gcc','g++']:
    wrapper=commands/name
    wrapper.write_text('#!/bin/sh\nexport CPATH="/workspace/.openwrt-onboarding/host/usr/include${CPATH:+:$CPATH}"\nexport LIBRARY_PATH="/workspace/.openwrt-onboarding/host/usr/lib/x86_64-linux-gnu${LIBRARY_PATH:+:$LIBRARY_PATH}"\nexec /usr/bin/'+name+' "$@"\n')
    wrapper.chmod(0o755)
for name,target in [('cc','gcc'),('c++','g++')]:
    link=commands/name
    if not link.exists():link.symlink_to(target)
NATIVE

cat > "$setup_root/activate.sh" <<'ACTIVATE'
# Source this file in each command shell used for OpenWrt host development.
export OPENWRT_HOST_PREFIX=/workspace/.openwrt-onboarding/host
export PATH="/workspace/.openwrt-onboarding/bin:$OPENWRT_HOST_PREFIX/usr/bin:$PATH"
export LD_LIBRARY_PATH="$OPENWRT_HOST_PREFIX/usr/lib/x86_64-linux-gnu:$OPENWRT_HOST_PREFIX/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# Native compiler wrappers set include/library paths for native gcc and g++
# only. Keep cross-compiler include and library search environments untouched.
export PYTHONPATH="$OPENWRT_HOST_PREFIX/usr/lib/python3/dist-packages${PYTHONPATH:+:$PYTHONPATH}"
export PERL5LIB="$OPENWRT_HOST_PREFIX/usr/share/automake-1.17:$OPENWRT_HOST_PREFIX/usr/share/autoconf${PERL5LIB:+:$PERL5LIB}"
export BISON_PKGDATADIR="$OPENWRT_HOST_PREFIX/usr/share/bison"
export SWIG_LIB="$OPENWRT_HOST_PREFIX/usr/share/swig/4.3.0"
export autom4te_perllibdir="$OPENWRT_HOST_PREFIX/usr/share/autoconf"
export AC_MACRODIR="$OPENWRT_HOST_PREFIX/usr/share/autoconf"
export AUTOM4TE_CFG=/workspace/.openwrt-onboarding/autom4te.cfg
export trailer_m4="$OPENWRT_HOST_PREFIX/usr/share/autoconf/autoconf/trailer.m4"
export M4="$OPENWRT_HOST_PREFIX/usr/bin/m4"
export AUTOCONF="$OPENWRT_HOST_PREFIX/usr/bin/autoconf"
export AUTOHEADER="$OPENWRT_HOST_PREFIX/usr/bin/autoheader"
export AUTOM4TE="$OPENWRT_HOST_PREFIX/usr/bin/autom4te"
export AUTOMAKE="$OPENWRT_HOST_PREFIX/usr/bin/automake"
export AUTOMAKE_LIBDIR="$OPENWRT_HOST_PREFIX/usr/share/automake-1.17"
export ACLOCAL="$OPENWRT_HOST_PREFIX/usr/bin/aclocal"
export ACLOCAL_AUTOMAKE_DIR="$OPENWRT_HOST_PREFIX/usr/share/aclocal-1.17"
export ACLOCAL_PATH="$OPENWRT_HOST_PREFIX/usr/share/aclocal${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
export _lt_pkgdatadir="$OPENWRT_HOST_PREFIX/usr/share/libtool"
export gettext_datadir="$OPENWRT_HOST_PREFIX/usr/share/gettext"
export CCACHE_DIR=/workspace/.openwrt-onboarding/ccache
OPENWRT_BUILD_JOBS=$(nproc)
if [ "$OPENWRT_BUILD_JOBS" -gt 4 ]; then OPENWRT_BUILD_JOBS=4; fi
export OPENWRT_BUILD_JOBS
umask 022
ACTIVATE

cat > "$setup_root/verify-host.sh" <<'VERIFY'
#!/bin/bash
set -euo pipefail
source /workspace/.openwrt-onboarding/activate.sh
# These discovery paths apply only to this native-host validation process.
export PKG_CONFIG_PATH="$OPENWRT_HOST_PREFIX/usr/lib/x86_64-linux-gnu/pkgconfig:$OPENWRT_HOST_PREFIX/usr/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CMAKE_PREFIX_PATH="$OPENWRT_HOST_PREFIX/usr${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
test "$(umask)" = 0022
probe_dir=$(mktemp -d /tmp/openwrt-host-check.XXXXXX)
trap 'rm -rf -- "$probe_dir"' EXIT
cd "$probe_dir"
touch case-sensitive
test ! -e CASE-SENSITIVE

cat > host.c <<'C'
#include <argp.h>
#include <fts.h>
#include <obstack.h>
#include <libintl.h>
#include <ncurses.h>
#include <zlib.h>
#include <openssl/sha.h>
#include <libelf.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    const unsigned char data[] = "abc";
    unsigned char compressed[128], restored[128], digest[SHA256_DIGEST_LENGTH];
    uLongf compressed_size = sizeof(compressed), restored_size = sizeof(restored);
    const unsigned char expected[SHA256_DIGEST_LENGTH] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    if (compress(compressed, &compressed_size, data, sizeof(data)) != Z_OK) return 1;
    if (uncompress(restored, &restored_size, compressed, compressed_size) != Z_OK) return 2;
    if (restored_size != sizeof(data) || memcmp(restored, data, sizeof(data))) return 3;
    if (!SHA256(data, 3, digest) || memcmp(digest, expected, sizeof(expected))) return 4;
    if (!curses_version() || elf_version(EV_CURRENT) == EV_NONE) return 5;
    puts("host-libraries-ok");
    return 0;
}
C
gcc -Wall -Wextra -Werror host.c -o host-static-zlib -Wl,-Bstatic -lz -Wl,-Bdynamic -lncurses -lcrypto -lelf
test "$(./host-static-zlib)" = host-libraries-ok

cat > host.cpp <<'CPP'
#include <algorithm>
#include <filesystem>
#include <thread>
#include <vector>
int main() {
    std::vector<int> values{3,1,2};
    std::thread worker([&] { std::sort(values.begin(), values.end()); });
    worker.join();
    return values != std::vector<int>({1,2,3}) || !std::filesystem::exists("host.c");
}
CPP
cat > CMakeLists.txt <<'CMAKE'
cmake_minimum_required(VERSION 3.16)
project(openwrt_host_probe LANGUAGES C CXX)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Curses REQUIRED)
find_package(Threads REQUIRED)
find_path(ELF_INCLUDE_DIR libelf.h REQUIRED)
find_library(ELF_LIBRARY elf REQUIRED)
add_executable(host host.c)
target_include_directories(host PRIVATE ${CURSES_INCLUDE_DIRS} ${ELF_INCLUDE_DIR})
target_link_libraries(host PRIVATE ZLIB::ZLIB OpenSSL::Crypto ${CURSES_LIBRARIES} ${ELF_LIBRARY})
add_executable(cxx host.cpp)
target_compile_features(cxx PRIVATE cxx_std_17)
target_link_libraries(cxx PRIVATE Threads::Threads)
enable_testing()
add_test(NAME host_libraries COMMAND host)
add_test(NAME cxx_runtime COMMAND cxx)
set_tests_properties(cxx_runtime PROPERTIES WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
CMAKE
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel "$OPENWRT_BUILD_JOBS"
ctest --test-dir build --output-on-failure

cat > parser.y <<'YACC'
%{
#include <stdio.h>
int yylex(void);
void yyerror(const char *s) { fprintf(stderr, "%s\n", s); }
%}
%token NUMBER
%%
input: NUMBER '+' NUMBER '\n' { printf("%d\n", $1+$3); };
%%
int main(void) { return yyparse(); }
YACC
cat > lexer.l <<'LEX'
%option noyywrap
%{
#include <stdlib.h>
#include "parser.tab.h"
%}
%%
[0-9]+ { yylval=atoi(yytext); return NUMBER; }
[ \t]+ ;
.|\n { return yytext[0]; }
%%
LEX
bison --defines parser.y
flex lexer.l
gcc parser.tab.c lex.yy.c -o parser -lfl
test "$(printf '2+3\n' | ./parser)" = 5
printf 'Flex/Bison generated parser: PASS\n'

mkdir autotools
cd autotools
cat > configure.ac <<'AC'
AC_INIT([openwrt-host-probe], [1.0])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
LT_INIT
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
AC
cat > Makefile.am <<'AM'
lib_LTLIBRARIES = libprobe.la
libprobe_la_SOURCES = probe.c
check_PROGRAMS = autotools-probe
autotools_probe_SOURCES = main.c
autotools_probe_LDADD = libprobe.la
TESTS = autotools-probe
AM
printf 'int probe(void) { return 7; }\n' > probe.c
printf 'int probe(void); int main(void) { return probe() != 7; }\n' > main.c
autoreconf --install
./configure --prefix="$probe_dir/install"
make --jobs="$OPENWRT_BUILD_JOBS" check
test -f test-suite.log
rg '^# TOTAL: 1$' test-suite.log
rg '^# PASS:  1$' test-suite.log
cd "$probe_dir"

cat > probe.i <<'SWIG'
%module probe
%inline %{
int add(int left, int right) { return left + right; }
%}
SWIG
swig -python probe.i
test -s probe_wrap.c
test -s probe.py
cat > messages.po <<'PO'
msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\n"

msgid "build"
msgstr "compile"
PO
msgfmt --check-format -o messages.mo messages.po
msgunfmt messages.mo > messages.roundtrip.po
rg -q '^msgstr "compile"$' messages.roundtrip.po
mkdir synced
rsync host.c synced/
cmp host.c synced/host.c
test "$(printf '2\n3\n' | gawk '{total += $1} END {print total}')" = 5
python3 -c 'import setuptools, ntpath'
perl -MData::Dumper -MFindBin -MFile::Copy -MFile::Compare -MThread::Queue -MIPC::Cmd -e 1
printf 'OpenWrt host prerequisites: PASS (C/C++ libraries, CMake/CTest 2/2, Autotools 1/1, Flex/Bison, SWIG, gettext, rsync, Python, Perl).\n'
VERIFY

source "$setup_root/activate.sh"
bash "$setup_root/verify-host.sh" > "$setup_root/validation.log" 2>&1
tail -1 "$setup_root/validation.log"
