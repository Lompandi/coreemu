
#include "emulator.h"

Emulator::Emulator() : Uc_(nullptr), CurrentDump_(nullptr) {}

Emulator::~Emulator() {
    if (Uc_) {
        uc_close(Uc_);
        Uc_ = nullptr;
    }
}

void Emulator::CodeHook(uc_engine*,
    uint64_t address,
    uint32_t size,
    void* user_data) {

    auto Emu = reinterpret_cast<Emulator*>(user_data);
    if (Emu->CodeExecutionCallback_) {
        Emu->CodeExecutionCallback_(Emu);
    }
    // fmt::println("[CODE] {:#016x} (+{})", address, size);
}

void Emulator::MemReadHook(uc_engine*,
    uc_mem_type,
    uint64_t address,
    int size,
    int64_t,
    void* user_data) {

    auto Emu = reinterpret_cast<Emulator*>(user_data);
    if (Emu->MemReadCallback_) {
        Emu->MemReadCallback_(Emu, address, size);
    }

    // fmt::println("[READ] {:#016x} ({} bytes)", address, size);
}

void Emulator::MemWriteHook(uc_engine*,
    uc_mem_type,
    uint64_t address,
    int size,
    int64_t value,
    void* user_data) {

    auto Emu = reinterpret_cast<Emulator*>(user_data);
    if (Emu->MemWriteCallback_) {
        Emu->MemWriteCallback_(Emu, address, size);
    }
    // fmt::println("[WRITE] {:#016x} ({} bytes) = {:#x}",
    //    address, size, value);
}

bool Emulator::MemUnmappedHook(uc_engine* uc,
    uc_mem_type type, uint64_t address, int size, int64_t, void* user_data) {

    auto Emu = reinterpret_cast<Emulator*>(user_data);
    uint64_t page = PageAlign(address);

    //
    // we will immediately halt the execution if we can't map a page
    //
    std::array<uint8_t, PAGE_SIZE> buffer{};
    if (!Emu->CurrentDump_->ReadVirtualMemory(page, buffer.data(), buffer.size())) {
        return false;
    }

    if (uc_mem_map(uc, page, PAGE_SIZE,
        UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC) != UC_ERR_OK) {
        return false;
    }

    uc_mem_write(uc, page, buffer.data(), buffer.size());

    if (!Emu->MappedPages_.contains(page)) {
        Emu->MappedPages_.insert(page);
    }

    return true;
}

bool Emulator::init(const CoreDumpFile& DumpFile) {
    CurrentDump_ = &DumpFile;

    if (uc_open(UC_ARCH_X86, UC_MODE_64, &Uc_) != UC_ERR_OK) {
        return false;
    }

    uc_hook code_hook, mem_read_hook, mem_write_hook, unmapped_hook;
    uc_hook_add(Uc_, &code_hook, UC_HOOK_CODE,
        (void*)CodeHook, this, 1, 0);

    uc_hook_add(Uc_, &mem_read_hook,
        UC_HOOK_MEM_READ,
        (void*)MemReadHook, this, 1, 0);

    uc_hook_add(Uc_, &mem_write_hook,
        UC_HOOK_MEM_WRITE,
        (void*)MemWriteHook, this, 1, 0);

    uc_hook_add(Uc_, &unmapped_hook,
        UC_HOOK_MEM_UNMAPPED, (void*)MemUnmappedHook, this, 1, 0);

    return true;
}

//
bool Emulator::start(const CoreDumpFile& CoreDump, uint64_t End, std::optional<size_t> Count) {

    // set all GPA from the dumpfile
    Registers Regs = CoreDump.GetRegisters();

    load_regs(Regs);

    if (PreEmulationCallback_) {
        PreEmulationCallback_(this);
    }

    __try {
        uc_err err = uc_emu_start(Uc_, Regs.Rip, End, 0, Count ? *Count : 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    if (PostEmulationCallback_) {
        PostEmulationCallback_(this);
    }

    return true;
}

void Emulator::load_regs(const Registers& r) {
    uc_reg_write(Uc_, UC_X86_REG_RAX, &r.Rax);
    uc_reg_write(Uc_, UC_X86_REG_RBX, &r.Rbx);
    uc_reg_write(Uc_, UC_X86_REG_RCX, &r.Rcx);
    uc_reg_write(Uc_, UC_X86_REG_RDX, &r.Rdx);
    uc_reg_write(Uc_, UC_X86_REG_RSI, &r.Rsi);
    uc_reg_write(Uc_, UC_X86_REG_RDI, &r.Rdi);
    uc_reg_write(Uc_, UC_X86_REG_RSP, &r.Rsp);
    uc_reg_write(Uc_, UC_X86_REG_RBP, &r.Rbp);
    uc_reg_write(Uc_, UC_X86_REG_R8, &r.R8);
    uc_reg_write(Uc_, UC_X86_REG_R9, &r.R9);
    uc_reg_write(Uc_, UC_X86_REG_R10, &r.R10);
    uc_reg_write(Uc_, UC_X86_REG_R11, &r.R11);
    uc_reg_write(Uc_, UC_X86_REG_R12, &r.R12);
    uc_reg_write(Uc_, UC_X86_REG_R13, &r.R13);
    uc_reg_write(Uc_, UC_X86_REG_R14, &r.R14);
    uc_reg_write(Uc_, UC_X86_REG_R15, &r.R15);
    uc_reg_write(Uc_, UC_X86_REG_RIP, &r.Rip);
    uc_reg_write(Uc_, UC_X86_REG_EFLAGS, &r.Rflags);
}