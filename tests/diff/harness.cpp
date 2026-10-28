// lendiza differential-test harness.
//
// Reads tests/diff/out/streams.tsv (mode TAB hex TAB srcid TAB count) and
// decodes each stream linearly through the extern "C" ABI - one decode per
// expected instruction, exactly what a length-disassembly consumer would do.
//
// Output, one line per attempted step:
//   srcid TAB step TAB result
// where result is the decimal instruction length or an error code (E0
// insufficient buffer, E1 undefined instruction, E2 internal). Decoding of a
// stream stops at the first error, so later steps simply have no line.
//
// Build (no CMake / GTest needed - the ABI header is plain C):
//   MSVC:   cmd /c tests\diff\build.bat   (x64 Native Tools prompt, or let
//                                          the script tell you how to call it)
//   MinGW:  sh tests/diff/build.sh
#include "lendiza_export.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char** argv)
{
    const char* path = argc > 1 ? argv[1] : "streams.tsv";
    FILE* f = std::fopen(path, "r");
    if (!f) {
        std::fprintf(stderr, "cannot open %s\n", path);
        return 1;
    }

    char line[1 << 16];
    while (std::fgets(line, sizeof line, f)) {
        // mode TAB hex TAB srcid TAB count
        char* tab1 = std::strchr(line, '\t');
        if (!tab1) continue;
        char* tab2 = std::strchr(tab1 + 1, '\t');
        if (!tab2) continue;
        char* tab3 = std::strchr(tab2 + 1, '\t');
        if (!tab3) continue;
        *tab1 = *tab2 = *tab3 = '\0';
        const int mode = std::atoi(line);
        const char* hexs = tab1 + 1;
        const char* srcid = tab2 + 1;
        const long count = std::strtol(tab3 + 1, nullptr, 10);

        std::vector<uint8_t> bytes;
        for (const char* p = hexs; p[0] && p[1]; p += 2) {
            const int hi = hexval(p[0]), lo = hexval(p[1]);
            if (hi < 0 || lo < 0) break;
            bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }

        size_t offset = 0;
        for (long step = 0; step < count; ++step) {
            const size_t r = (mode == 64 ? lendiza_disasm_x64 : lendiza_disasm_x86)
                                 (bytes.data() + offset, bytes.size() - offset);
            const char* tag = nullptr;
            if (r == LENDIZA_ERR_INSUFFICIENT_BUFFER) tag = "E0";
            else if (r == LENDIZA_ERR_UNDEFINED_INSTRUCTION) tag = "E1";
            else if (r == LENDIZA_ERR_UNKNOWN) tag = "E2";
            if (tag) std::printf("%s\t%ld\t%s\n", srcid, step, tag);
            else std::printf("%s\t%ld\t%zu\n", srcid, step, r);
            if (r >= LENDIZA_ERR_INSUFFICIENT_BUFFER) break;
            offset += r;
            if (offset >= bytes.size() && step + 1 < count) break;
        }
    }
    std::fclose(f);
    return 0;
}
