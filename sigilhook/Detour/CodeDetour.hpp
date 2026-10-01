// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#pragma once

#include "sigilhook/Detour/ADetour.hpp"

namespace SIGILHOOK {

class CodeDetour final : public Detour {
public:
    CodeDetour(uint64_t address, uint64_t callback, uint64_t* userTrampVar, Mode mode)
        : Detour(address, callback, userTrampVar, mode) {}

    Mode getArchType() const override;
    bool hook() override;
    bool unHook() override;
    bool reHook() override;

    uint32_t getOverwrittenBytes() const { return m_overwrittenBytes; }

private:
    static constexpr uint32_t kMaximumOverwriteBytes = 64;
    uint32_t m_overwrittenBytes = 0;
    uint32_t m_relocatedBytes = 0;
};

} // namespace SIGILHOOK
