# Copyright (c) 2026 StackAndPointer
# SPDX-License-Identifier: MIT

if(WIN32 AND SIGILHOOK_FEATURE_ANGELSCRIPT)
    option(SIGILHOOK_BUILD_INJECTOR_DLL "Build the injectable SigilHook.dll runtime" ON)
    option(SIGILHOOK_BUILD_API_SMOKE_TEST "Build the exported C API smoke test" ON)
    option(SIGILHOOK_BUILD_SCRIPT_SMOKE_TEST "Build the AngelScript runtime smoke test" ON)
    option(SIGILHOOK_BUILD_NATIVE_BINDING_TEST "Build the native DLL binding test fixtures" ON)
    option(SIGILHOOK_BUILD_HEADER_GENERATOR_TESTS "Build the Python header generator tests" ON)
    set(SIGILHOOK_RUNTIME_DEFAULT_STOP_TIMEOUT_MS 5000 CACHE STRING
        "Default timeout for stopping the AngelScript runtime")

    set(SIGILHOOK_RUNTIME_SCRIPT_DIR "${CMAKE_CURRENT_BINARY_DIR}/SigilHook")
    file(MAKE_DIRECTORY "${SIGILHOOK_RUNTIME_SCRIPT_DIR}")
    configure_file("${PROJECT_SOURCE_DIR}/scripts/SigilHook.ash" "${SIGILHOOK_RUNTIME_SCRIPT_DIR}/SigilHook.ash" COPYONLY)
    configure_file("${PROJECT_SOURCE_DIR}/scripts/SigilHookReload.bat" "${CMAKE_CURRENT_BINARY_DIR}/SigilHookReload.bat" COPYONLY)

    if(SIGILHOOK_BUILD_HEADER_GENERATOR_TESTS)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        enable_testing()
        add_test(NAME HeaderToAshUnitTests
            COMMAND ${Python3_EXECUTABLE} -m unittest discover -s tools/tests -v)
        set_tests_properties(HeaderToAshUnitTests PROPERTIES
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    endif()

    if(SIGILHOOK_BUILD_NATIVE_BINDING_TEST)
        add_library(NativeBindingTestDll SHARED
            ${PROJECT_SOURCE_DIR}/Examples/NativeBindingTestDll/NativeBindingTest.cpp)
        set_target_properties(NativeBindingTestDll PROPERTIES
            OUTPUT_NAME NativeBindingTestDll
            CXX_STANDARD 20
            CXX_STANDARD_REQUIRED ON)
        target_include_directories(NativeBindingTestDll PRIVATE
            ${PROJECT_SOURCE_DIR}/Examples/NativeBindingTestDll)
        if(MSVC AND SIGILHOOK_BUILD_STATIC_RUNTIME)
            set_target_properties(NativeBindingTestDll PROPERTIES
                MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        endif()
    endif()

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
        target_compile_definitions(SigilHookDll PRIVATE
            SIGILHOOK_BUILDING_DLL=1
            SIGILHOOK_RUNTIME_DEFAULT_STOP_TIMEOUT_MS=${SIGILHOOK_RUNTIME_DEFAULT_STOP_TIMEOUT_MS}
        )
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
        install(FILES ${PROJECT_SOURCE_DIR}/scripts/SigilHookReload.bat DESTINATION bin)

        if(SIGILHOOK_BUILD_API_SMOKE_TEST)
            add_executable(SigilHookApiSmokeTest
                ${PROJECT_SOURCE_DIR}/Examples/SigilHookApiSmokeTest/main.cpp
            )
            target_compile_features(SigilHookApiSmokeTest PRIVATE cxx_std_20)
            target_include_directories(SigilHookApiSmokeTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
            target_link_libraries(SigilHookApiSmokeTest PRIVATE SigilHookDll)
            if(SIGILHOOK_BUILD_NATIVE_BINDING_TEST)
                target_include_directories(SigilHookApiSmokeTest PRIVATE
                    ${PROJECT_SOURCE_DIR}/Examples/NativeBindingTestDll)
                target_link_libraries(SigilHookApiSmokeTest PRIVATE NativeBindingTestDll)
            endif()
            if(TARGET NativeBindingTestDll)
                target_compile_definitions(SigilHookApiSmokeTest PRIVATE SIGILHOOK_NATIVE_BINDING_TEST=1)
            endif()
            if(SIGILHOOK_USE_EXTERNAL_ASMJIT)
                target_link_libraries(SigilHookApiSmokeTest PRIVATE asmjit::asmjit)
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
            file(MAKE_DIRECTORY "${SIGILHOOK_SCRIPT_TEST_DIR}/nested")
            file(MAKE_DIRECTORY "${SIGILHOOK_SCRIPT_TEST_DIR}")
            configure_file(${PROJECT_SOURCE_DIR}/scripts/SigilHook.ash "${SIGILHOOK_SCRIPT_TEST_DIR}/SigilHook.ash" COPYONLY)
            set(SIGILHOOK_GENERATED_BINDING "${SIGILHOOK_SCRIPT_TEST_DIR}/NativeBindingTest.ash")
            if(SIGILHOOK_BUILD_HEADER_GENERATOR_TESTS AND SIGILHOOK_BUILD_NATIVE_BINDING_TEST)
                find_package(Python3 REQUIRED COMPONENTS Interpreter)
                add_custom_command(OUTPUT "${SIGILHOOK_GENERATED_BINDING}"
                    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/header_to_ash.py
                        Examples/NativeBindingTestDll/NativeBindingTest.h
                        --dll NativeBindingTestDll.dll
                        --output "${SIGILHOOK_GENERATED_BINDING}"
                        --arch $<IF:$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>,x64,x86>
                    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                    DEPENDS ${PROJECT_SOURCE_DIR}/tools/header_to_ash.py
                        ${PROJECT_SOURCE_DIR}/Examples/NativeBindingTestDll/NativeBindingTest.h
                        ${PROJECT_SOURCE_DIR}/Examples/NativeBindingTestDll/sigilhook_annotations.h
                    VERBATIM
                    COMMENT "Generating NativeBindingTest.ash")
                add_custom_target(GenerateNativeBindingAsh DEPENDS "${SIGILHOOK_GENERATED_BINDING}")
                add_test(NAME HeaderToAshGeneratedBindingCheck
                    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/header_to_ash.py
                        Examples/NativeBindingTestDll/NativeBindingTest.h
                        --dll NativeBindingTestDll.dll
                        --output "${SIGILHOOK_GENERATED_BINDING}"
                        --arch $<IF:$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>,x64,x86> --check)
                set_tests_properties(HeaderToAshGeneratedBindingCheck PROPERTIES
                    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
            endif()
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/main.as "${SIGILHOOK_SCRIPT_TEST_DIR}/main.as" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/include/Nested.ash "${SIGILHOOK_SCRIPT_TEST_DIR}/include/Nested.ash" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/include/ModuleShared.ash "${SIGILHOOK_SCRIPT_TEST_DIR}/include/ModuleShared.ash" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/10-test.as "${SIGILHOOK_SCRIPT_TEST_DIR}/10-test.as" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/nested/recursive.as "${SIGILHOOK_SCRIPT_TEST_DIR}/nested/recursive.as" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/11-status.as "${SIGILHOOK_SCRIPT_TEST_DIR}/11-status.as" COPYONLY)
            configure_file(${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/scripts/native-binding.as "${SIGILHOOK_SCRIPT_TEST_DIR}/native-binding.as" COPYONLY)
            add_executable(SigilHookScriptSmokeTest
                ${PROJECT_SOURCE_DIR}/Examples/SigilHookScriptSmokeTest/main.cpp
            )
            if(TARGET GenerateNativeBindingAsh)
                add_dependencies(SigilHookScriptSmokeTest GenerateNativeBindingAsh)
            endif()
            target_compile_features(SigilHookScriptSmokeTest PRIVATE cxx_std_20)
            target_compile_definitions(SigilHookScriptSmokeTest PRIVATE SIGILHOOK_TEST_SCRIPT_DIRECTORY=L"${SIGILHOOK_SCRIPT_TEST_DIR}")
            target_include_directories(SigilHookScriptSmokeTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
            target_link_libraries(SigilHookScriptSmokeTest PRIVATE SigilHookDll)
            if(SIGILHOOK_BUILD_NATIVE_BINDING_TEST)
                target_include_directories(SigilHookScriptSmokeTest PRIVATE
                    ${PROJECT_SOURCE_DIR}/Examples/NativeBindingTestDll)
                target_link_libraries(SigilHookScriptSmokeTest PRIVATE NativeBindingTestDll)
            endif()
            if(TARGET NativeBindingTestDll)
                target_compile_definitions(SigilHookScriptSmokeTest PRIVATE SIGILHOOK_NATIVE_BINDING_TEST=1)
            endif()
            if(SIGILHOOK_USE_EXTERNAL_ASMJIT)
                target_link_libraries(SigilHookScriptSmokeTest PRIVATE asmjit::asmjit)
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

            add_executable(SigilHookHotReloadSmokeTest
                ${PROJECT_SOURCE_DIR}/Examples/SigilHookHotReloadSmokeTest/main.cpp
            )
            target_compile_features(SigilHookHotReloadSmokeTest PRIVATE cxx_std_20)
            target_compile_definitions(SigilHookHotReloadSmokeTest PRIVATE
                SIGILHOOK_TEST_SCRIPT_DIRECTORY=L"${SIGILHOOK_SCRIPT_TEST_DIR}")
            target_include_directories(SigilHookHotReloadSmokeTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
            target_link_libraries(SigilHookHotReloadSmokeTest PRIVATE SigilHookDll)
            if(SIGILHOOK_USE_EXTERNAL_ASMJIT)
                target_link_libraries(SigilHookHotReloadSmokeTest PRIVATE asmjit::asmjit)
            else()
                target_link_libraries(SigilHookHotReloadSmokeTest PRIVATE asmjit)
            endif()
            if(MSVC)
                if(SIGILHOOK_BUILD_STATIC_RUNTIME)
                    set_target_properties(SigilHookHotReloadSmokeTest PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
                else()
                    set_target_properties(SigilHookHotReloadSmokeTest PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
                endif()
            endif()
            add_test(NAME SigilHookHotReloadSmokeTest COMMAND SigilHookHotReloadSmokeTest)
            set_tests_properties(SigilHookHotReloadSmokeTest PROPERTIES ENVIRONMENT "SIGILHOOK_DISABLE_AUTOLOAD=1")

            add_executable(SigilHookUsageExamplesCompileTest
                ${PROJECT_SOURCE_DIR}/Examples/Scripts/UsageExamplesCompileCheck.cpp
            )
            target_compile_features(SigilHookUsageExamplesCompileTest PRIVATE cxx_std_20)
            target_compile_definitions(SigilHookUsageExamplesCompileTest PRIVATE
                SIGILHOOK_USAGE_EXAMPLE_DIRECTORY=L"${PROJECT_SOURCE_DIR}/Examples/Scripts/UsageExamples"
                SIGILHOOK_USAGE_HEADER=L"${PROJECT_SOURCE_DIR}/scripts/SigilHook.ash")
            target_include_directories(SigilHookUsageExamplesCompileTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
            if(SIGILHOOK_USE_EXTERNAL_ASMJIT)
                target_link_libraries(SigilHookUsageExamplesCompileTest PRIVATE SigilHookDll)
            else()
                target_link_libraries(SigilHookUsageExamplesCompileTest PRIVATE SigilHookDll asmjit)
            endif()
            add_test(NAME SigilHookUsageExamplesCompileTest COMMAND SigilHookUsageExamplesCompileTest)
            set_tests_properties(SigilHookUsageExamplesCompileTest PROPERTIES ENVIRONMENT "SIGILHOOK_DISABLE_AUTOLOAD=1")
            add_executable(SigilHookUsageSmokeTest
                ${PROJECT_SOURCE_DIR}/Examples/SigilHookUsageSmokeTest/main.cpp
            )
            target_compile_features(SigilHookUsageSmokeTest PRIVATE cxx_std_20)
            target_compile_definitions(SigilHookUsageSmokeTest PRIVATE
                SIGILHOOK_USAGE_HEADER=L"${PROJECT_SOURCE_DIR}/scripts/SigilHook.ash")
            target_include_directories(SigilHookUsageSmokeTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
            if(SIGILHOOK_USE_EXTERNAL_ASMJIT)
                target_link_libraries(SigilHookUsageSmokeTest PRIVATE SigilHookDll)
            else()
                target_link_libraries(SigilHookUsageSmokeTest PRIVATE SigilHookDll asmjit)
            endif()
            if(MSVC)
                if(SIGILHOOK_BUILD_STATIC_RUNTIME)
                    set_target_properties(SigilHookUsageSmokeTest PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
                else()
                    set_target_properties(SigilHookUsageSmokeTest PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
                endif()
            endif()
            add_test(NAME SigilHookUsageSmokeTest COMMAND SigilHookUsageSmokeTest)
            set_tests_properties(SigilHookUsageSmokeTest PROPERTIES ENVIRONMENT "SIGILHOOK_DISABLE_AUTOLOAD=1")
        endif()
    endif()
endif()
