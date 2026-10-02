// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// Two ways to run script code inside the original function:
//   - shHookEntryContinue: callback first, then continue through the trampoline
//   - shHookInstructionStatus: real instruction-level hook with a trampoline

#include "SigilHook.ash"

const uint64 ENTRY_CONTINUE_TARGET = 0x00401000;
const string ENTRY_CONTINUE_SIGNATURE = "void:void*";

const uint64 INSTRUCTION_TARGET = 0x00401020;  // must be an instruction boundary
const string INSTRUCTION_SIGNATURE = "int:int";

uint64 g_entryContinueHook = SH_INVALID_HANDLE;
uint64 g_instructionHook = SH_INVALID_HANDLE;
uint64 g_instructionTrampoline = 0;

void onEntryContinue() {
    // Runs before the original entry. Keep the original body by leaving
    // shKeepOriginal() at its default, or use continueOriginal() on the
    // SHCallContext when you want to be explicit.
    shSetReturn(0);
    shKeepOriginal();
}

void onInstruction() {
    // Runs at the instruction-level hook point.
    shKeepOriginal();
}

void setupMidHook() {
    g_entryContinueHook = shHookEntryContinue(
        ENTRY_CONTINUE_TARGET, "void onEntryContinue()",
        ENTRY_CONTINUE_SIGNATURE, "usercall:ret=none;arg0=ecx");
    if (!shIsValidHook(g_entryContinueHook)) {
        shLog("entry-continue hook failed: " + shLastError());
    }

    uint64 overwritten = 0;
    const uint8 status = shHookInstructionStatus(
        INSTRUCTION_TARGET, "void onInstruction()", INSTRUCTION_SIGNATURE,
        g_instructionHook, g_instructionTrampoline, overwritten, "cdecl");
    if (status != SH_OK) {
        shLog("instruction hook failed: " + shStatusString(status));
    }
}

void unloadMidHook() {
    if (shIsValidHook(g_entryContinueHook)) {
        shDestroyHook(g_entryContinueHook);
        g_entryContinueHook = SH_INVALID_HANDLE;
    }
    if (shIsValidHook(g_instructionHook)) {
        shDestroyHook(g_instructionHook);
        g_instructionHook = SH_INVALID_HANDLE;
    }
}
