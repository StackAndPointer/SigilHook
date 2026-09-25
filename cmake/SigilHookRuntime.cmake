if(WIN32 AND POLYHOOK_FEATURE_ANGELSCRIPT)
    option(POLYHOOK_BUILD_INJECTOR_DLL "Build the injectable SigilHook.dll runtime" ON)
    option(POLYHOOK_BUILD_API_SMOKE_TEST "Build the exported C API smoke test" ON)

    if(POLYHOOK_BUILD_INJECTOR_DLL)
        add_library(SigilHookDll SHARED
            ${PROJECT_SOURCE_DIR}/sources/SigilHookApi.cpp
            ${PROJECT_SOURCE_DIR}/sources/SigilHookRuntime.cpp
            ${PROJECT_SOURCE_DIR}/sources/SigilHookDllMain.cpp
            ${PROJECT_SOURCE_DIR}/third_party/angelscript/sdk/add_on/scriptstdstring/scriptstdstring.cpp
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
        )
        target_link_libraries(SigilHookDll PRIVATE ${PROJECT_NAME} ${POLYHOOK_ANGELSCRIPT_TARGET})

        if(MSVC)
            target_compile_options(SigilHookDll PRIVATE /W4 /Z7)
            target_link_libraries(SigilHookDll PRIVATE -DEBUG)
            if(POLYHOOK_BUILD_STATIC_RUNTIME)
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

        if(POLYHOOK_BUILD_API_SMOKE_TEST)
            add_executable(SigilHookApiSmokeTest
                ${PROJECT_SOURCE_DIR}/Examples/SigilHookApiSmokeTest/main.cpp
            )
            target_compile_features(SigilHookApiSmokeTest PRIVATE cxx_std_20)
            target_include_directories(SigilHookApiSmokeTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
            target_link_libraries(SigilHookApiSmokeTest PRIVATE SigilHookDll)
            enable_testing()
            add_test(NAME SigilHookApiSmokeTest COMMAND SigilHookApiSmokeTest)
        endif()
    endif()
endif()
