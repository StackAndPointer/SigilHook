// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "SigilHook.ash"
#include "NativeBindingTest.ash"

void nativeBindingFail(const string &in message) {
    shSetSharedU64("nativeBindingBad", 1);
    shLog("native binding test failed: " + message);
}

void verifyNativeBinding() {
    if (SHNativeAdd(6, 7) != 13) nativeBindingFail("scalar int");
    if (SHNativeScale(1.5f) != 4.5) nativeBindingFail("float/double");
    const int32 narrowLength = SHNativeTextLength("SigilHook");
    if (narrowLength != 9) nativeBindingFail("narrow string");
    if (SHNativeWideLength("SigilHook") != 9) nativeBindingFail("wide string");
    if (SHNativeEchoPointer(shSharedU64("nativeBindingPointer")) !=
        shSharedU64("nativeBindingPointer")) nativeBindingFail("pointer");

    if (SHNativeCdeclSum(7, 9) != 402) nativeBindingFail("cdecl");
    if (SHNativeStdcallSum(7, 9) != 402) nativeBindingFail("stdcall");
    if (SHNativeFastcallSum(7, 9) != 402) nativeBindingFail("fastcall");
    if (SHNativeThiscallSum(7, 9) != 402) nativeBindingFail("thiscall");
    if (SHNativeVectorcallSum(7, 9) != 402) nativeBindingFail("vectorcall");

    SHNativeS1 one;
    one.value = 10;
    SHNativeS1 oneResult = SHNativeEcho1(one);
    if (oneResult.value != 11) nativeBindingFail("record 1");

    SHNativeS4 four;
    four.value = 20;
    SHNativeS4 fourResult = SHNativeEcho4(four);
    if (fourResult.value != 24) nativeBindingFail("record 4");

    SHNativeS8 eight;
    eight.value = 30;
    SHNativeS8 eightResult = SHNativeEcho8(eight);
    if (eightResult.value != 38) nativeBindingFail("record 8");

    SHNativeS16 sixteen;
    sixteen.low = 40;
    sixteen.high = 50;
    SHNativeS16 sixteenResult = SHNativeEcho16(sixteen);
    if (sixteenResult.low != 56 || sixteenResult.high != 82) {
        nativeBindingFail("record 16");
    }

    SHNativeS32 thirtyTwo;
    thirtyTwo.a = 60;
    thirtyTwo.b = 70;
    thirtyTwo.c = 80;
    thirtyTwo.d = 90;
    SHNativeS32 thirtyTwoResult = SHNativeEcho32(thirtyTwo);
    if (thirtyTwoResult.a != 61 || thirtyTwoResult.b != 72 ||
        thirtyTwoResult.c != 83 || thirtyTwoResult.d != 94) {
        nativeBindingFail("record 32");
    }

    SHNativePacked5 packed;
    packed.tag = 2;
    packed.value = 100;
    SHNativePacked5 packedResult = SHNativeEchoPacked(packed);
    if (packedResult.tag != 3 || packedResult.value != 105) {
        nativeBindingFail("packed record");
    }
}
