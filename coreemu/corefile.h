#pragma once

#include <memory>
#include <string>
#include <cstring>
#include <algorithm>
#include <optional>

#include <fmt/format.h>
#include <LIEF/ELF.hpp>

struct Registers {
    uint64_t Rax;
    uint64_t Rbx;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;
    uint64_t Rip;
    uint64_t Rflags;
};

class CoreDumpFile {
public:
    explicit CoreDumpFile() = default;

    bool parse(const std::string& path);

    LIEF::ELF::Binary* binary() const {
        return Binary_.get();
    }

    // Reads virtual memory from PT_LOAD segments
    bool ReadVirtualMemory(uint64_t address, void* out, size_t size) const;

    // Convenience: dump memory as QWORDs
    void DumpMemoryQwords(uint64_t address, size_t qwords) const;

    // Dump mapped regions from NT_FILE
    void DumpMappings() const;

    // Dump registers from NT_PRSTATUS
    void DumpRegistersAndStack(size_t stack_qwords = 16) const;

    // std::string GetName(uint64_t Address) const;

    Registers GetRegisters() const {
        return CoreRegs_;
    }

    struct ResolvedName {
        std::string Name;
        uint64_t Offset;
        uint64_t FullAddr;
    };

    std::optional<ResolvedName> ResolveModule(uint64_t addr) const;

    // TODO: Currently this only handle PIE off executables
    // void ResolveFunctionName(const char* ModulePath, ResolvedName& Name) const;

private:
    Registers CoreRegs_;

    mutable std::unordered_map<uint64_t, std::vector<uint8_t>> PageCache_;

    std::unique_ptr<LIEF::ELF::Binary> Binary_;
};
