// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include <angelscript.h>

#include <iostream>

namespace {
void MessageCallback(const asSMessageInfo* message, void*) {
    std::cerr << message->section << ':' << message->row << ':' << message->col << ": "
              << message->message << '\n';
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

    std::cout << "AngelScript runtime is ready\n";
    return 0;
}
