// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "sigilhook/Detour/CodeDetour.hpp"

#include <cstring>

namespace SIGILHOOK {

Mode CodeDetour::getArchType() const {
#if defined(SIGILHOOK_ARCH_X64)
    return Mode::x64;
#else
    return Mode::x86;
#endif
}

namespace {

uint32_t minimumJumpSize() {
    return sizeof(void*) == 8 ? 25u : 5u;
}


} // namespace

bool CodeDetour::hook() {
    Log::log("CodeDetour address: " + int_to_hex(m_fnAddress) + "\n", ErrorLevel::INFO);

    const uint32_t minimumPatchBytes = minimumJumpSize();
    if (m_fnAddress == 0 || m_fnCallback == 0) {
        Log::log("CodeDetour requires a non-zero address and callback", ErrorLevel::SEV);
        return false;
    }

    insts_t instructions;
    try {
        instructions = m_disasm.disassemble(
            m_fnAddress, m_fnAddress, m_fnAddress + kMaximumOverwriteBytes, *this);
    } catch (...) {
        Log::log("CodeDetour disassembly failed", ErrorLevel::SEV);
        return false;
    }

    if (instructions.empty()) {
        Log::log("CodeDetour could not decode any instruction at the target address", ErrorLevel::SEV);
        return false;
    }

    uint64_t overwritten = 0;
    insts_t prologue;
    for (const auto& instruction : instructions) {
        if (instruction.size() == 0) break;
        prologue.push_back(instruction);
        overwritten += instruction.size();
        if (overwritten >= minimumPatchBytes) break;
    }

    if (overwritten < minimumPatchBytes || prologue.empty()) {
        Log::log("CodeDetour could not cover the minimum patch width", ErrorLevel::SEV);
        return false;
    }

    if (overwritten > kMaximumOverwriteBytes) {
        Log::log("CodeDetour overwrite region exceeds the safety limit", ErrorLevel::SEV);
        return false;
    }

    for (const auto& instruction : prologue) {
        const std::string mnemonic = instruction.getMnemonic();
        if (mnemonic == "ret" || mnemonic == "retf" || mnemonic == "iret") {
            Log::log("CodeDetour refuses to overwrite a return instruction", ErrorLevel::SEV);
            return false;
        }
        if (instruction.isBranching() && !instruction.isIndirect()) {
            Log::log("CodeDetour does not overwrite relative control-flow instructions", ErrorLevel::SEV);
            return false;
        }
    }

    m_originalInsts = prologue;
    m_overwrittenBytes = static_cast<uint32_t>(overwritten);
    m_hookSize = m_overwrittenBytes;

    const uint64_t trampolineSize = 128u;
    m_trampoline = reinterpret_cast<uint64_t>(new unsigned char[trampolineSize]);
    m_trampolineSz = static_cast<uint16_t>(trampolineSize);
    m_relocatedBytes = m_overwrittenBytes;

    MemoryProtector trampolineProtection(
        m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

    uint64_t cursor = m_trampoline;
    insts_t relocated;
    for (const auto& original : prologue) {
        Instruction instruction = original;
        instruction.setAddress(cursor);
        if (instruction.hasDisplacement() || instruction.isIndirect()) {
            Log::log(
                "CodeDetour refuses to overwrite a displacement/indirect instruction at " +
                int_to_hex(original.getAddress()), ErrorLevel::SEV);
            return false;
        }
        relocated.push_back(instruction);
        cursor += instruction.size();
    }

    std::vector<uint8_t> trampolineBytes;
    for (const auto& instruction : relocated) {
        const auto& bytes = instruction.getBytes();
        trampolineBytes.insert(trampolineBytes.end(), bytes.begin(), bytes.end());
    }

    const uint64_t resumeAddress = m_fnAddress + m_overwrittenBytes;
    const auto resume = makeAgnosticJmp(cursor, resumeAddress);
    for (const auto& instruction : resume) {
        const auto& bytes = instruction.getBytes();
        trampolineBytes.insert(trampolineBytes.end(), bytes.begin(), bytes.end());
    }

    if (trampolineBytes.size() > m_trampolineSz) {
        Log::log("CodeDetour trampoline buffer is too small", ErrorLevel::SEV);
        return false;
    }

    MemoryProtector writeProtection(
        m_trampoline, trampolineBytes.size(), ProtFlag::RWX, *this, false);
    std::memcpy(reinterpret_cast<void*>(m_trampoline), trampolineBytes.data(), trampolineBytes.size());

    MemoryProtector prot(m_fnAddress, m_hookSize, ProtFlag::RWX, *this);
    m_hookInsts = makeAgnosticJmp(m_fnAddress, m_fnCallback);
    ZydisDisassembler::writeEncoding(m_hookInsts, *this);

    m_nopProlOffset = static_cast<uint16_t>(calcInstsSz(m_hookInsts));
    if (m_hookSize > m_nopProlOffset) {
        const auto nops = make_nops(m_fnAddress + m_nopProlOffset, static_cast<uint16_t>(m_hookSize - m_nopProlOffset));
        ZydisDisassembler::writeEncoding(nops, *this);
    }

    *m_userTrampVar = m_trampoline;
    m_hooked = true;
    return true;
}

bool CodeDetour::unHook() {
    if (!m_hooked) return true;

    MemoryProtector prot(m_fnAddress, m_hookSize, ProtFlag::RWX, *this);
    ZydisDisassembler::writeEncoding(m_originalInsts, *this);

    if (m_trampoline != 0) {
        delete[] reinterpret_cast<unsigned char*>(m_trampoline);
        m_trampoline = 0;
        m_trampolineSz = 0;
    }
    m_hooked = false;
    return true;
}

bool CodeDetour::reHook() {
    if (m_hookInsts.empty()) return false;

    MemoryProtector prot(m_fnAddress, m_hookSize, ProtFlag::RWX, *this);
    ZydisDisassembler::writeEncoding(m_hookInsts, *this);
    if (m_hookSize > m_nopProlOffset) {
        const auto nops = make_nops(m_fnAddress + m_nopProlOffset, static_cast<uint16_t>(m_hookSize - m_nopProlOffset));
        ZydisDisassembler::writeEncoding(nops, *this);
    }
    m_hooked = true;
    return true;
}

} // namespace SIGILHOOK
