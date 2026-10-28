#!/bin/sh
# Build the differential-test harness with MinGW/GCC from the repository root:
#   sh tests/diff/build.sh
# Binaries go to tests/diff/out/ (gitignored).
set -e
cd "$(dirname "$0")"
mkdir -p out
${CXX:-g++} -std=c++17 -O2 -Wall -Wextra -I../../include \
    harness.cpp ../../src/lendiza.cpp -o out/harness.exe
