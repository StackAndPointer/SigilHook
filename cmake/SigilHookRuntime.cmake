# Copyright (c) 2026 StackAndPointer
# SPDX-License-Identifier: MIT

if(WIN32 AND SIGILHOOK_FEATURE_ANGELSCRIPT)
    option(SIGILHOOK_BUILD_INJECTOR_DLL "Build the injectable SigilHook.dll runtime" ON)
    option(SIGILHOOK_BUILD_API_SMOKE_TEST "Build the exported C API smoke test" ON)
    option(SIGILHOOK_BUILD_SCRIPT_SMOKE_TEST "Build the AngelScript runtime smoke test" ON)

    set(SIGILHOOK_RUNTIME_SCRIPT_DIR "${CMAKE_CURRENT_BINARY_DIR}/SigilHook")
    file(MAKE_DIRECTORY "${SIGILHOOK_RUNTIME_SCRIPT_DIR}")
    configure_file("${PROJECT_SOURCE_DIR}/scripts/SigilHook.ash" "${SIGILHOOK_RUNTIME_SCRIPT_DIR}/SigilHook.ash" COPYONLY)

    if(SIGILHOOK_BUILD_INJECTOR_DLL)
        add_library(SigilHookDll SHARED
            ${PROJECT_SOURCE_DIR}/sources/SigilHookApi.cpp
            ${PROJECT_SOURCE_DIR}/sources/SigilHookRuntime.cpp
            ${PROJECT_SOURCE_DIR}/sources/SigilHookDllMain.cpp
            ${PROJECT_SOURCE_DIR}/third_party/angelscript/sdk/add_on/scriptstdstring/scriptstdstring.cpp
            ${PROJECT_SOURCE_DIR}/third_party/angelscript/sdk/add_on/scriptarray/scriptarray.cpp
        )
        set_target_properties(SigilHookDll PROPERTIES
            OUTPUT_NAME SigilHook
            ARCHIVE_OUTPUT_NAME SigilHookImport
        )
        target_compile_features(SigilHookDll PRIVATE cxx_std_20)
        target_compile_definitions(SigilHookDll PRIVATE SIGILHOOK_BUILDING_DLL=1)
        target_include_directories(SigilHookDll PRIVATE
            ${PROJECT_SOURCE_DIR}/include
            ${PROJECT_SOURCE_DIR}/third_party/angelscript/sdk/angelscript/include
            ${PROJECT_SOURCE_DIR}/third_party/angelscript/sdk/add_on/scriptstdstring
            ${PROJECT_SOURCE_DIR}/third_party/angelscript/sdk/add_on/scriptarray
        )
        target_link_libraries(SigilHookDll PRIVATE ${PROJECT_NAME} ${SIGILHOOK_ANGELSCRIPT_TARGET})

        if(MSVC)
            target_compile_options(SigilHookDll PRIVATE /W4 /Z7)
            target_link_libraries(SigilHookDll PRIVATE -DEBUG)
            if(SIGILHOOK_BUILD_STATIC_RUNTIME)
                set_target_properties(SigilHookDll PROPERTIES
                    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
                )
            endif()
        endif()

        install(TARGETS SigilHookDll
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib
        )
        install(FILES ${PROJECT_SOURCE_DIR}/include/sigilhook.h DESTINATION include)
        install(FILES ${PROJECT_SOURCE_DIR}/scripts/SigilHook.ash DESTINATION bin/SigilHook)

        if(SIGILHOOK_BUILD_API_SMOKE_TEST)
            add_executable(SigilHookApiSmokeTest
                ${PROJECT_SOURCE_DIR}/Examples/SigilHookApiSmokeTest/main.cpp
            )
            target_compile_features(SigilHookApiSmokeTest PRIVATE cxx_std_20)
            target_include_directories(SigilHookApiSmokeTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
            target_link_libraries(SigilHookApiSmokeTest PRIVATE SigilHookDll)
            if(SIGILHOOK_USE_EXTERNAL_ASMJIT)
                target_link_libraries(SigilHookApiSmokeTest PRIVATE ${ASMJIT_LIBRARY})
                target_include_directories(SigilHookApiSmokeTest PRIVATE ${ASMJIT_INCLUDE_DIR})
            else()
                target_link_libraries(SigilHookApiSmokeTest PRIVATE asmjit)
            endif()
            if(MSVC)
                if(SIGILHOOK_BUILD_STATIC_RUNTIME)
                    set_target_properties(SigilHookApiSmokeTest PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
                else()
                    set_target_properties(SigilHookApiSmokeTest PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
                endif()
            endif()
            enable_testing()
            add_test(NAME SigilHookApiSmokeTest COMMAND SigilHookApiSmokeTest)
            set_tests_properties(SigilHookApiSmokeTest PROPERTIES ENVIRONMENT "SIGILHOOK_DISABLE_AUTOLOAD=1")
        endif()

        if(SIGILHOOK_BUILD_SCRIPT_SMOKE_TEST)
            set(SIGILHOOK_SCRIPT_TEST_DIR "${CMAKE_CURRENT_BINARY_DIR}/SigilHookScriptSmokeTestScripts")
            file(MAKE_DIRECTORY "${SIGILHOOK_SCRIPT_TEST_DIR}")
            configure_file(${PROJECT_SOURCE_DIR}/scripts/SigilHook.ash "${SIGILHOOK_SCRIPT_TEST_DIR}/SigilHook.ash" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/main.as "${SIGILHOOK_SCRIPT_TEST_DIR}/main.as" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/include/Nested.ash "${SIGILHOOK_SCRIPT_TEST_DIR}/include/Nested.ash" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/include/ModuleShared.ash "${SIGILHOOK_SCRIPT_TEST_DIR}/include/ModuleShared.ash" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/10-test.as "${SIGILHOOK_SCRIPT_TEST_DIR}/10-test.as" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/11-status.as "${SIGILHOOK_SCRIPT_TEST_DIR}/11-status.as" COPYONLY)
            add_executable(SigilHookScriptSmokeTest
                ${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/main.cpp
            )
            target_compile_features(SigilHookScriptSmokeTest PRIVATE cxx_std_20)
            target_compile_definitions(SigilHookScriptSmokeTest PRIVATE SIGILHOOK_TEST_SCRIPT_DIRECTORY=L"${SIGILHOOK_SCRIPT_TEST_DIR}")
            target_include_directories(SigilHookScriptSmokeTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
            target_link_libraries(SigilHookScriptSmokeTest PRIVATE SigilHookDll)
            if(SIGILHOOK_USE_EXTERNAL_ASMJIT)
                target_link_libraries(SigilHookScriptSmokeTest PRIVATE ${ASMJIT_LIBRARY})
                target_include_directories(SigilHookScriptSmokeTest PRIVATE ${ASMJIT_INCLUDE_DIR})
            else()
                target_link_libraries(SigilHookScriptSmokeTest PRIVATE asmjit)
            endif()
            if(MSVC)
                if(SIGILHOOK_BUILD_STATIC_RUNTIME)
                    set_target_properties(SigilHookScriptSmokeTest PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
                else()
                    set_target_properties(SigilHookScriptSmokeTest PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
                endif()
            endif()
            enable_testing()
            add_test(NAME SigilHookScriptSmokeTest COMMAND SigilHookScriptSmokeTest)
            set_tests_properties(SigilHookScriptSmokeTest PROPERTIES ENVIRONMENT "SIGILHOOK_DISABLE_AUTOLOAD=1")
        endif()
    endif()
endif()
