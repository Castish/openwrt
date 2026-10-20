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
