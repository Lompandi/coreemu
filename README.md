# coreemu
A simple core-dump emulation library I make for reverse engineering


# Example Usage

```c++

#include <fmt/format.h>

#include "include/corefile.h"
#include "include/emulator.h"

#pragma comment(lib, "coreemu.lib")

int main() {
    CoreDumpFile file;
    file.parse("E:\\test_coreemu\\x64\\Debug\\core.1723");

    Emulator emu;
    emu.init(file);
    emu.set_exec_callback([](Emulator* emu) {
        auto value = emu->rip();
        fmt::println("PC: {:#016x}", value);
    });

    emu.set_mem_rd_callback([](Emulator* emu, uint64_t addr, size_t size) {
        fmt::println("READ: {:#016x} {}", addr, size);
    });

    emu.start(file, 0, 1000);
}

```
