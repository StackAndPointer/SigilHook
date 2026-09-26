// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include <angelscript.h>

#include <iostream>

namespace {
void MessageCallback(const asSMessageInfo* message, void*) {
    std::cerr << message->section << ':' << message->row << ':' << message->col << ": "
              << message->message << '\n';
}

int RunTwoModuleSmoke() {
    asIScriptEngine* engine = asCreateScriptEngine();
    if (engine == nullptr ||
        engine->SetMessageCallback(asFUNCTION(MessageCallback), nullptr, asCALL_CDECL) < 0) {
        std::cerr << "Failed to create the two-module AngelScript engine\n";
        if (engine != nullptr) engine->ShutDownAndRelease();
        return 1;
    }

    asIScriptModule* provider = engine->GetModule("ProviderModule", asGM_ALWAYS_CREATE);
    if (provider == nullptr ||
        provider->AddScriptSection(
            "provider.as",
            "int providerState = 0;\n"
            "void setProviderState(int value) { providerState = value; }\n"
            "int providerSum(int value) { return providerState + value; }\n") < 0 ||
        provider->Build() < 0) {
        std::cerr << "Failed to build the ProviderModule\n";
        engine->ShutDownAndRelease();
        return 1;
    }

    asIScriptModule* consumer = engine->GetModule("ConsumerModule", asGM_ALWAYS_CREATE);
    if (consumer == nullptr ||
        consumer->AddScriptSection(
            "consumer.as",
            "import void setProviderState(int) from \"ProviderModule\";\n"
            "import int providerSum(int) from \"ProviderModule\";\n"
            "int run() { setProviderState(37); return providerSum(5); }\n") < 0 ||
        consumer->Build() < 0 ||
        consumer->BindAllImportedFunctions() < 0) {
        std::cerr << "Failed to build or bind the ConsumerModule\n";
        engine->ShutDownAndRelease();
        return 1;
    }

    asIScriptFunction* function = consumer->GetFunctionByDecl("int run()");
    asIScriptContext* context = engine->CreateContext();
    if (function == nullptr || context == nullptr || context->Prepare(function) < 0 ||
        context->Execute() != asEXECUTION_FINISHED) {
        std::cerr << "Failed to execute the cross-module ConsumerModule function\n";
        if (context != nullptr) context->Release();
        engine->ShutDownAndRelease();
        return 1;
    }

    const int result = static_cast<int>(context->GetReturnDWord());
    const int stateIndex = provider->GetGlobalVarIndexByName("providerState");
    const auto* state = stateIndex < 0
        ? nullptr
        : static_cast<const int*>(provider->GetAddressOfGlobalVar(static_cast<asUINT>(stateIndex)));
    const int stateValue = state == nullptr ? 0 : *state;
    context->Release();
    engine->ShutDownAndRelease();

    if (result != 42 || state == nullptr || stateValue != 37) {
        std::cerr << "Cross-module function or shared state check failed\n";
        return 1;
    }
    return 0;
}
}

int main() {
    asIScriptEngine* engine = asCreateScriptEngine();
    if (engine == nullptr) {
        std::cerr << "Failed to create the AngelScript engine\n";
        return 1;
    }

    if (engine->SetMessageCallback(asFUNCTION(MessageCallback), nullptr, asCALL_CDECL) < 0) {
        std::cerr << "Failed to register the AngelScript message callback\n";
        engine->ShutDownAndRelease();
        return 1;
    }

    asIScriptModule* module = engine->GetModule("smoke", asGM_ALWAYS_CREATE);
    if (module == nullptr ||
        module->AddScriptSection("smoke", "void main() {}") < 0 ||
        module->Build() < 0) {
        std::cerr << "Failed to build the AngelScript smoke script\n";
        engine->ShutDownAndRelease();
        return 1;
    }

    asIScriptFunction* function = module->GetFunctionByDecl("void main()");
    asIScriptContext* context = engine->CreateContext();
    if (function == nullptr || context == nullptr || context->Prepare(function) < 0) {
        std::cerr << "Failed to prepare the AngelScript smoke function\n";
        if (context != nullptr) {
            context->Release();
        }
        engine->ShutDownAndRelease();
        return 1;
    }

    const int result = context->Execute();
    context->Release();
    engine->ShutDownAndRelease();

    if (result != asEXECUTION_FINISHED) {
        std::cerr << "AngelScript smoke function did not finish normally\n";
        return 1;
    }

    if (RunTwoModuleSmoke() != 0) {
        return 1;
    }

    std::cout << "AngelScript runtime is ready\n";
    return 0;
}
