#!/bin/sh
# Builds and runs test/host_check.cpp on the host (needs the rweather/Crypto
# sources that `pio run` downloads into .pio/libdeps).
# macOS: if linking fails with "unknown architecture", point SDKROOT at an
# older SDK, e.g. SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
set -e
cd "$(dirname "$0")/.."
C=.pio/libdeps/specter/Crypto
out="${TMPDIR:-/tmp}/specter_host_check"
c++ -std=c++11 -O1 -I"$C" -o "$out" test/host_check.cpp src/acl.cpp \
    src/meshcrypto/meshcrypto.cpp "$C/AES128.cpp" "$C/AESCommon.cpp" \
    "$C/SHA256.cpp" "$C/Hash.cpp" "$C/Crypto.cpp" "$C/BlockCipher.cpp"
"$out"
