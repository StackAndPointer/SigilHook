//
// Created by steve on 7/4/17.
//
#pragma once

#include "sigilhook/SigilHookOs.hpp"
#include "sigilhook/Detour/ADetour.hpp"
#include "sigilhook/Enums.hpp"
#include "sigilhook/Instruction.hpp"

using namespace std::placeholders;

namespace SIGILHOOK {

class x86Detour : public Detour {
public:
    x86Detour(uint64_t fnAddress, uint64_t fnCallback, uint64_t* userTrampVar);

    virtual ~x86Detour() = default;

    virtual bool hook() override;

    Mode getArchType() const override;

protected:
    bool fixSpecialCases(insts_t& prologue);
    bool fixCallRoutineReturningSP(Instruction& callInst, const insts_t& routine);
    bool fixCallInlineReturningSP(Instruction& callInst);

    bool makeTrampoline(insts_t& prologue, insts_t& trampolineOut);
};

}
