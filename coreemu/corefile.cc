#pragma once

#include <filesystem>
#include <fmt/format.h>

#include "corefile.h"

namespace fs = std::filesystem;

bool CoreDumpFile::parse(const std::string& Path) {
    Binary_ = LIEF::ELF::Parser::parse(Path);
    if (!Binary_) {
        fmt::println("failed to parse the binary.");
        return false;
    }

    for (const auto& note : Binary_->notes()) {
        if (!LIEF::ELF::CorePrStatus::classof(&note))
            continue;

        const auto& pr =
            static_cast<const LIEF::ELF::CorePrStatus&>(note);

        const auto& regs = pr.register_values();
        using R = LIEF::ELF::CorePrStatus::Registers::X86_64;

#define REG(x) regs.at((uint64_t)R::x)
        CoreRegs_.Rip = REG(RIP);
        CoreRegs_.Rsp = REG(RSP);
        CoreRegs_.Rbp = REG(RBP);
        CoreRegs_.Rax = REG(RAX);
        CoreRegs_.Rbx = REG(RBX);
        CoreRegs_.Rcx = REG(RCX);
        CoreRegs_.Rdx = REG(RDX);
        CoreRegs_.Rsi = REG(RSI);
        CoreRegs_.Rdi = REG(RDI);
        CoreRegs_.R8 = REG(R8);
        CoreRegs_.R9 = REG(R9);
        CoreRegs_.R10 = REG(R10);
        CoreRegs_.R11 = REG(R11);
        CoreRegs_.R12 = REG(R12);
        CoreRegs_.R13 = REG(R13);
        CoreRegs_.R14 = REG(R14);
        CoreRegs_.R15 = REG(R15);
#undef REG
    }
}

bool CoreDumpFile::ReadVirtualMemory(uint64_t address, void* out, size_t size) const {
    uint8_t* out_bytes = reinterpret_cast<uint8_t*>(out);

    while (size > 0) {
        uint64_t page_base = address & ~(0x1000 - 1);
        size_t page_offset = address - page_base;
        size_t to_copy = std::min(0x1000 - page_offset, size);

        auto it = PageCache_.find(page_base);
        std::vector<uint8_t>* page;

        if (it != PageCache_.end()) {
            page = &it->second;
        }
        else {
            // load page
            std::vector<uint8_t> page_data(0x1000, 0);
            bool page_found = false;

            for (const auto& segment : Binary_->segments()) {
                // if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD)
                    // continue;

                uint64_t seg_start = segment.virtual_address();
                uint64_t seg_end = seg_start + segment.virtual_size();

                if (page_base >= seg_end || page_base + 0x1000 <= seg_start)
                    continue; // no overlap

                page_found = true;

                uint64_t copy_start = std::max(seg_start, page_base);
                uint64_t copy_end = std::min(seg_end, page_base + 0x1000);

                size_t seg_offset = copy_start - seg_start;
                size_t page_offset_inner = copy_start - page_base;
                size_t copy_size = copy_end - copy_start;

                const auto& content = segment.content();
                if (seg_offset + copy_size > content.size())
                    return false;

                std::memcpy(page_data.data() + page_offset_inner,
                    content.data() + seg_offset,
                    copy_size);
            }

            if (!page_found)
                return false;

            auto [insert_it, _] = PageCache_.emplace(page_base, std::move(page_data));
            page = &insert_it->second;
        }

        std::memcpy(out_bytes, page->data() + page_offset, to_copy);

        address += to_copy;
        out_bytes += to_copy;
        size -= to_copy;
    }

    return true;
}

void CoreDumpFile::DumpMemoryQwords(uint64_t address, size_t qwords) const {
    fmt::println("\nReading {} QWORDs @ {:#016x}", qwords, address);

    for (size_t i = 0; i < qwords; ++i) {
        uint64_t value = 0;
        if (!ReadVirtualMemory(address + i * 8, &value, sizeof(value)))
            break;

        fmt::println("{:#016x}: {:#016x}",
            address + i * 8, value);
    }
}

void CoreDumpFile::DumpMappings() const {
    for (const auto& note : Binary_->notes()) {
        if (!LIEF::ELF::CoreFile::classof(&note))
            continue;

        const auto& core =
            static_cast<const LIEF::ELF::CoreFile&>(note);

        for (const auto& entry : core) {
            fmt::println("{}: [{:#016x}, {:#016x}]",
                entry.path, entry.start, entry.end);
        }
    }
}

void CoreDumpFile::DumpRegistersAndStack(size_t stack_qwords) const {
    for (const auto& note : Binary_->notes()) {
        if (!LIEF::ELF::CorePrStatus::classof(&note))
            continue;

        const auto& pr =
            static_cast<const LIEF::ELF::CorePrStatus&>(note);

        const auto& regs = pr.register_values();
        using R = LIEF::ELF::CorePrStatus::Registers::X86_64;

#define REG(x) regs.at((uint64_t)R::x)
        fmt::println("RIP: {:#016x}", REG(RIP));
        fmt::println("RSP: {:#016x}", REG(RSP));
        fmt::println("RBP: {:#016x}", REG(RBP));
        fmt::println("RAX: {:#016x}", REG(RAX));
        fmt::println("RBX: {:#016x}", REG(RBX));
        fmt::println("RCX: {:#016x}", REG(RCX));
        fmt::println("RDX: {:#016x}", REG(RDX));
        fmt::println("RSI: {:#016x}", REG(RSI));
        fmt::println("RDI: {:#016x}", REG(RDI));
        fmt::println("R8 : {:#016x}", REG(R8));
        fmt::println("R9 : {:#016x}", REG(R9));
        fmt::println("R10: {:#016x}", REG(R10));
        fmt::println("R11: {:#016x}", REG(R11));
        fmt::println("R12: {:#016x}", REG(R12));
        fmt::println("R13: {:#016x}", REG(R13));
        fmt::println("R14: {:#016x}", REG(R14));
        fmt::println("R15: {:#016x}", REG(R15));
#undef REG
    }
}

std::optional<CoreDumpFile::ResolvedName>
CoreDumpFile::ResolveModule(uint64_t addr) const {
    for (const auto& note : Binary_->notes()) {
        if (!LIEF::ELF::CoreFile::classof(&note))
            continue;

        const auto& core =
            static_cast<const LIEF::ELF::CoreFile&>(note);

        for (const auto& entry : core) {
            if (addr >= entry.start && addr < entry.end) {
                return ResolvedName{
                    entry.path,
                    addr - entry.start,
                    addr
                };
            }
        }
    }
    return std::nullopt;
}

/*void CoreDumpFile::ResolveFunctionName(const char* ModulePath, ResolvedName& Name) const {
    std::unique_ptr<LIEF::ELF::Binary> elf;

    try {
        elf = LIEF::ELF::Parser::parse(ModulePath);
    }
    catch (...) {
        return;
    }

    if (!elf)
        return;

    const LIEF::ELF::Symbol* best = nullptr;

    auto scan_sym = [&](LIEF::ELF::Binary::it_symbols syms) {
        for (const auto& sym : syms) {
            if (sym.value() == 0 || sym.name().empty())
                continue;

            if (!best || sym.value() > best->value() && sym.value() < Name.FullAddr) {
                best = &sym;
            }
        }
        };

    auto scan_dynsym = [&](LIEF::ELF::Binary::it_dynamic_symbols syms) {
        for (const auto& sym : syms) {
            if (sym.value() == 0 || sym.name().empty())
                continue;
        }
        };

    scan_sym(elf->symbols());               // .symtab
    scan_dynsym(elf->dynamic_symbols());    // .dynsym

    if (!best)
        return;

    Name.Name = fmt::format("{}!{}", Name.Name, best->name());
    Name.Offset = Name.FullAddr - best->value();
}*/

/*std::string CoreDumpFile::GetName(uint64_t Address) const {
    std::optional<ResolvedName> Ra = ResolveModule(Address);
    if (Ra) {
        Ra->Name = fs::path(Ra->Name).filename().string();
        //TODO: get this make this can autoamtially resolve the name
        ResolveFunctionName("E:\\Bds Reverse Engineering\\rhop\\x64\\Release\\chall", Ra.value());
        return fmt::format("{}+{:#x}", Ra->Name, Ra->Offset);
    }
    return fmt::format("{:#x}", Address);
}*/