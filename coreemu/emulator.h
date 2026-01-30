#pragma once

#include <optional>
#include <functional>
#include <unordered_set>
#include <unicorn/unicorn.h>

#include "corefile.h"

static constexpr uint64_t PAGE_SIZE = 0x1000;

class Emulator {
public:
    using mem_access_callback = std::function<void(Emulator*, uint64_t, size_t)>;

    Emulator();

    ~Emulator();

    bool init(const CoreDumpFile& DumpFile);

    bool start(const CoreDumpFile& core_dump, uint64_t End, std::optional<size_t> Count = std::nullopt);

    void load_regs(const Registers& r);

    void set_pre_emu_callback(std::function<void(Emulator*)> cb) {
        PreEmulationCallback_ = cb;
    }

    void set_post_emu_callback(std::function<void(Emulator*)> cb) {
        PostEmulationCallback_ = cb;
    }

    void set_exec_callback(std::function<void(Emulator*)> cb) {
        CodeExecutionCallback_ = cb;
    }

    void set_mem_rd_callback(mem_access_callback cb) {
        MemReadCallback_ = cb;
    }

    void set_mem_wr_callback(mem_access_callback cb) {
        MemWriteCallback_ = cb;
    }

#define UC_REG(Name) get_reg(UC_X86_REG_##Name)

#define FLAG_BIT_GET(Name, BitPos) \
uint64_t Name() { return (rflags() >> BitPos) & 1; }

    // Status flags getters
    FLAG_BIT_GET(cf, 0)   // Carry Flag
    FLAG_BIT_GET(pf, 2)   // Parity Flag
    FLAG_BIT_GET(af, 4)   // Auxiliary Carry
    FLAG_BIT_GET(zf, 6)   // Zero Flag
    FLAG_BIT_GET(sf, 7)   // Sign Flag
    FLAG_BIT_GET(of, 11)  // Overflow Flag

#undef FLAG_BIT_GET

    uint64_t rflags() {
        return UC_REG(RFLAGS);
    }

    uint64_t rip() {
        return UC_REG(RIP);
    }

    uint64_t rax() {
        return UC_REG(RAX);
    }

    uint64_t rbx() {
        return UC_REG(RBX);
    }

    uint64_t rcx() {
        return UC_REG(RCX);
    }

    uint64_t rdx() {
        return UC_REG(RDX);
    }

    uint64_t rsi() {
        return UC_REG(RSI);
    }

    uint64_t rdi() {
        return UC_REG(RDI);
    }

    uint64_t rsp() {
        return UC_REG(RSP);
    }

    uint64_t rbp() {
        return UC_REG(RBP);
    }

    uint64_t r8() {
        return UC_REG(R8);
    }

    uint64_t r9() {
        return UC_REG(R9);
    }

    uint64_t r10() {
        return UC_REG(R10);
    }

    uint64_t r11() {
        return UC_REG(R11);
    }

    uint64_t r12() {
        return UC_REG(R12);
    }

    uint64_t r13() {
        return UC_REG(R13);
    }

    uint64_t r14() {
        return UC_REG(R14);
    }

    uint64_t r15() {
        return UC_REG(R15);
    }
#undef UC_REG

#define UC_SETREG(Name) set_reg(UC_X86_REG_##Name, value)

#define FLAG_BIT_SET(Name, BitPos) \
void Name(bool value) { \
    uint64_t f = rflags(); \
    if (value) f |= (1ULL << BitPos); \
    else       f &= ~(1ULL << BitPos); \
    rflags(f); \
}

    FLAG_BIT_SET(cf, 0)   // Carry Flag
    FLAG_BIT_SET(pf, 2)   // Parity Flag
    FLAG_BIT_SET(af, 4)   // Auxiliary Carry
    FLAG_BIT_SET(zf, 6)   // Zero Flag
    FLAG_BIT_SET(sf, 7)   // Sign Flag
    FLAG_BIT_SET(of, 11)  // Overflow Flag

#undef FLAG_BIT_SET

    void rflags(uint64_t value) {
        UC_SETREG(RFLAGS);
    }

    void rip(uint64_t value) {
        UC_SETREG(RIP);
    }

    void rax(uint64_t value) {
        UC_SETREG(RAX);
    }

    void rbx(uint64_t value) {
        UC_SETREG(RBX);
    }

    void rcx(uint64_t value) {
        UC_SETREG(RCX);
    }

    void rdx(uint64_t value) {
        UC_SETREG(RDX);
    }

    void rsi(uint64_t value) {
        UC_SETREG(RSI);
    }

    void rdi(uint64_t value) {
        UC_SETREG(RDI);
    }

    void rsp(uint64_t value) {
        UC_SETREG(RSP);
    }

    void rbp(uint64_t value) {
        UC_SETREG(RBP);
    }

    void r8(uint64_t value) {
        UC_SETREG(R8);
    }

    void r9(uint64_t value) {
        UC_SETREG(R9);
    }

    void r10(uint64_t value) {
        UC_SETREG(R10);
    }

    void r11(uint64_t value) {
        UC_SETREG(R11);
    }

    void r12(uint64_t value) {
        UC_SETREG(R12);
    }

    void r13(uint64_t value) {
        UC_SETREG(R13);
    }

    void r14(uint64_t value) {
        UC_SETREG(R14);
    }

    void r15(uint64_t value) {
        UC_SETREG(R15);
    }
#undef UC_SETREG

    void set_reg(uc_x86_reg reg, uint64_t value) {
        uc_reg_write(Uc_, reg, &value);
    }

    uint64_t get_reg(uc_x86_reg reg) {
        uint64_t value = 0;
        uc_reg_read(Uc_, reg, &value);
        return value;
    }

    void stop() {
        uc_emu_stop(Uc_);
    }

    // Can be called only after the unicorn instance is initialized.
    void write_mem(uint64_t Address, void* Buffer, size_t Size) {
        // Force a page-in if the target location haven't yet
        if (!MappedPages_.contains(PageAlign(Address))) {
            MemUnmappedHook(Uc_, UC_MEM_WRITE_UNMAPPED, Address, Size, 0, this);
        }
        uc_mem_write(Uc_, Address, Buffer, Size);
    }

    void write_u64(uint64_t Address, uint64_t Value) {
        write_mem(Address, &Value, sizeof(Value));
    }

    void write_u32(uint64_t Address, uint32_t Value) {
        write_mem(Address, &Value, sizeof(Value));
    }

    void write_u16(uint64_t Address, uint16_t Value) {
        write_mem(Address, &Value, sizeof(Value));
    }

    void write_u8(uint64_t Address, uint8_t Value) {
        write_mem(Address, &Value, sizeof(Value));
    }

    void read_mem(uint64_t Address, void* Buffer, size_t Size) {
        // Force a page-in if the target location isn't mapped yet
        if (!MappedPages_.contains(PageAlign(Address))) {
            MemUnmappedHook(Uc_, UC_MEM_READ_UNMAPPED, Address, Size, 0, this);
        }
        uc_mem_read(Uc_, Address, Buffer, Size);
    }

    uint8_t read_u8(uint64_t Address) {
        uint8_t v;
        read_mem(Address, &v, sizeof(v));
        return v;
    }

    uint16_t read_u16(uint64_t Address) {
        uint16_t v;
        read_mem(Address, &v, sizeof(v));
        return v;
    }

    uint32_t read_u32(uint64_t Address) {
        uint32_t v;
        read_mem(Address, &v, sizeof(v));
        return v;
    }

    uint64_t read_u64(uint64_t Address) {
        uint64_t v;
        read_mem(Address, &v, sizeof(v));
        return v;
    }

private:

    static void CodeHook(uc_engine* uc,
        uint64_t address,
        uint32_t size,
        void* user_data);

    static void MemReadHook(uc_engine* uc,
        uc_mem_type type,
        uint64_t address,
        int size,
        int64_t value,
        void* user_data);

    static void MemWriteHook(uc_engine* uc,
        uc_mem_type type,
        uint64_t address,
        int size,
        int64_t value,
        void* user_data);

    static bool MemUnmappedHook(uc_engine* uc,
        uc_mem_type type,
        uint64_t address,
        int size,
        int64_t,
        void* user_data);

    static uint64_t PageAlign(uint64_t v) {
        return v & ~(PAGE_SIZE - 1);
    }

    uc_engine* Uc_;

    std::unordered_set<uint64_t> MappedPages_;

    std::function<void(Emulator*)> PreEmulationCallback_;

    std::function<void(Emulator*)> PostEmulationCallback_;

    std::function<void(Emulator*)> CodeExecutionCallback_;

    mem_access_callback MemReadCallback_;

    mem_access_callback MemWriteCallback_;

    const CoreDumpFile* CurrentDump_;
};