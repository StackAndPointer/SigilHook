// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// UsageExamples entry point. Only the root main.as may define main()/unload().
// Each example exposes a setup function; enable the ones you want here.

#include "SigilHook.ash"

void main() {
    shLog("SigilHook usage examples starting");

    setupEntryDetour();
    setupCallAnotherFunction();
    setupThiscallUsercall();
    setupSkipOriginal();
    setupMidHook();
    // setupRegistersXmmFlags();   // enable after you set a real target
    // setupNativeBinding();        // requires a generated wrapper header
    // setupMultiFileExamples();    // see 08-multi-file.as
}

void unload() {
    unloadEntryDetour();
    unloadCallAnotherFunction();
    unloadThiscallUsercall();
    unloadSkipOriginal();
    unloadMidHook();
    unloadRegistersXmmFlags();
    unloadNativeBinding();
    unloadMultiFileExamples();
    shLog("SigilHook usage examples unloaded");
}
