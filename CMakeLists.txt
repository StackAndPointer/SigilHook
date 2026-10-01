cmake_minimum_required(VERSION 3.15)

project(SigilHook)
string(TOLOWER ${PROJECT_NAME} LOWERCASE_PROJECT_NAME)
include(CMakePackageConfigHelpers)

if(WIN32)
	set(SIGILHOOK_OS "windows")
elseif(APPLE)
	set(SIGILHOOK_OS "macos")
elseif(UNIX)
	set(SIGILHOOK_OS "linux")
endif()

#
# Options
#
option(SIGILHOOK_BUILD_DLL "Build dll & lib instead of tests" ON)

option(SIGILHOOK_BUILD_SHARED_LIB "Build SigilHook as shared library" OFF)
option(SIGILHOOK_BUILD_SHARED_ASMTK "Build asmtk as shared libary" OFF)
option(SIGILHOOK_BUILD_SHARED_ASMJIT "Build asmjit as shared libary" ${SIGILHOOK_BUILD_SHARED_ASMTK})
option(SIGILHOOK_BUILD_SHARED_ZYDIS "Build zydis as shared libary" OFF)

option(SIGILHOOK_USE_EXTERNAL_ASMTK "Use an external AsmTK library" OFF)
option(SIGILHOOK_USE_EXTERNAL_ASMJIT "Use an external AsmJit library" ${SIGILHOOK_USE_EXTERNAL_ASMTK})
option(SIGILHOOK_USE_EXTERNAL_ANGELSCRIPT "Use external AngelScript library" OFF)
option(SIGILHOOK_USE_EXTERNAL_ZYDIS "Use external zydis libary" OFF)

option(SIGILHOOK_FEATURE_ANGELSCRIPT "Build the AngelScript runtime integration" ON)
option(SIGILHOOK_BUILD_ANGELSCRIPT_SMOKE_TEST "Build the AngelScript runtime smoke test" ON)

if(MSVC)
	option(SIGILHOOK_BUILD_STATIC_RUNTIME "Use static runtime" ON)
endif()

if(WIN32)
    option(SIGILHOOK_FEATURE_EXCEPTION "Implement all exception hooking functionality" ON)
    option(SIGILHOOK_FEATURE_PE "Implement all win pe hooking functionality" ON)
else()
    set(SIGILHOOK_FEATURE_EXCEPTION OFF)
    set(SIGILHOOK_FEATURE_PE OFF)
endif()
option(SIGILHOOK_FEATURE_DETOURS "Implement detour functionality" ON)
option(SIGILHOOK_FEATURE_INLINENTD "Support inline hooks without specifying typedefs by generating callback stubs at runtime with AsmJit" ON)
option(SIGILHOOK_FEATURE_VIRTUALS "Implement all virtual table hooking functionality" ON)
option(SIGILHOOK_BUILD_INTERACTIVE_TESTS
	"Build native tests that require an interactive desktop" OFF)

#
# ASMTK
#

function(add_asmjit_properties)
    if(MSVC)
        if(SIGILHOOK_BUILD_STATIC_RUNTIME)
            set_target_properties(asmjit PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        else()
            set_target_properties(asmjit PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
        endif()
    endif()
endfunction()

if(SIGILHOOK_FEATURE_DETOURS AND NOT SIGILHOOK_USE_EXTERNAL_ASMTK)
	if(NOT SIGILHOOK_USE_EXTERNAL_ASMJIT)
	    set(ASMJIT_DIR "${PROJECT_SOURCE_DIR}/asmjit")
		set(ASMJIT_EXTERNAL OFF)
	else()
		set(ASMJIT_EXTERNAL ON)
    endif()
	# asmjit and asmtk do not use `option`
	if(SIGILHOOK_BUILD_SHARED_ASMTK)
		set(ASMTK_STATIC OFF)
		set(ASMJIT_STATIC OFF)
    else()
		set(ASMTK_STATIC ON)
		set(ASMJIT_STATIC ON)
    endif()

    add_subdirectory(asmtk)
    add_asmjit_properties()

	if(MSVC)
		if(SIGILHOOK_BUILD_STATIC_RUNTIME)
			set_target_properties(asmtk PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
		else()
			set_target_properties(asmtk PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
		endif()
	endif()

endif()

#
# ASMJIT
#

if(SIGILHOOK_FEATURE_INLINENTD AND NOT SIGILHOOK_USE_EXTERNAL_ASMJIT)
    # Avoid including asmjit again if it was already included
    if(NOT TARGET asmjit)
        # asmjit doesn't use `option`
        if(SIGILHOOK_BUILD_SHARED_ASMJIT)
            set(ASMJIT_STATIC OFF)
        else()
            set(ASMJIT_STATIC ON)
        endif()

	add_subdirectory(asmjit)
        add_asmjit_properties()
    endif()
endif()

#
# Zydis
#

function(set_zycore_options)
	set(ZYCORE_BUILD_SHARED_LIB ${SIGILHOOK_BUILD_SHARED_ZYDIS} CACHE BOOL "" FORCE)
	set(ZYCORE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
	set(ZYCORE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
endfunction()

function(set_zydis_options)
	set(ZYDIS_BUILD_SHARED_LIB ${SIGILHOOK_BUILD_SHARED_ZYDIS} CACHE BOOL "" FORCE)
	set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
	set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
	set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
endfunction()

if(NOT SIGILHOOK_USE_EXTERNAL_ZYDIS)
	set_zycore_options()
	add_subdirectory(zydis/dependencies/zycore)
	set_zydis_options()
	add_subdirectory(zydis)

	if(MSVC)
		if(SIGILHOOK_BUILD_STATIC_RUNTIME)
			set_target_properties(Zycore PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
			set_target_properties(Zydis PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
		else()
			set_target_properties(Zycore PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
			set_target_properties(Zydis PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
		endif()
	endif()
endif()

#
# SigilHook
#

if(SIGILHOOK_BUILD_DLL)
	if(SIGILHOOK_BUILD_SHARED_LIB)
		add_library(${PROJECT_NAME} SHARED)
		set_target_properties(${PROJECT_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
	else()
		add_library(${PROJECT_NAME} STATIC)
	endif()
else()
	add_executable(${PROJECT_NAME})

	target_sources(${PROJECT_NAME} PRIVATE
			${PROJECT_SOURCE_DIR}/UnitTests/TestUtils.hpp
			${PROJECT_SOURCE_DIR}/UnitTests/TestUtils.cpp
	)

	# Interactive desktop tests are opt-in. CI also skips them explicitly.
	if("$ENV{CI}" STREQUAL "true" OR NOT SIGILHOOK_BUILD_INTERACTIVE_TESTS)
		target_compile_definitions(${PROJECT_NAME} PRIVATE SIGILHOOK_SKIP_INTERACTIVE_TESTS)
	endif()
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 20)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD_REQUIRED ON)

if(MSVC)
    if(SIGILHOOK_BUILD_STATIC_RUNTIME)
		set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
	else()
		set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
	endif()

	if(MSVC)
		  set(COMPILE_FLAGS_SigilHook "/W4 /Z7")
		  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
			set(COMPILE_FLAGS_SigilHook "/MP ${COMPILE_FLAGS_SigilHook}")
		  endif()

		  set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${COMPILE_FLAGS_SigilHook})
		  target_link_libraries(${PROJECT_NAME} PRIVATE optimized -DEBUG) # mhhm ya pdbs
	endif()

endif()

target_include_directories(${PROJECT_NAME}
    PUBLIC
		$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
    INTERFACE
		$<INSTALL_INTERFACE:include>
)

#Core

#
# AngelScript
#

if(SIGILHOOK_FEATURE_ANGELSCRIPT)
    if(SIGILHOOK_USE_EXTERNAL_ANGELSCRIPT)
        find_package(Angelscript CONFIG REQUIRED)
        set(SIGILHOOK_ANGELSCRIPT_TARGET Angelscript::angelscript)
    else()
        set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)
        set(AS_DISABLE_INSTALL ON CACHE BOOL "Disable installation of AngelScript" FORCE)
        add_subdirectory(third_party/angelscript/sdk/angelscript/projects/cmake)
        set(SIGILHOOK_ANGELSCRIPT_TARGET angelscript)

        if(MSVC)
            if(SIGILHOOK_BUILD_STATIC_RUNTIME)
                set_target_properties(angelscript PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
            else()
                set_target_properties(angelscript PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
            endif()
        endif()
    endif()
endif()


#Core
set(SIGILHOOK_CORE_HEADERS
        ${PROJECT_SOURCE_DIR}/sigilhook/Enums.hpp
        ${PROJECT_SOURCE_DIR}/sigilhook/IHook.hpp
        ${PROJECT_SOURCE_DIR}/sigilhook/Instruction.hpp
        ${PROJECT_SOURCE_DIR}/sigilhook/Misc.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/UID.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/ErrorLog.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/MemProtector.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/MemAccessor.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/FBAllocator.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/RangeAllocator.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/Tests/TestEffectTracker.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/Tests/StackCanary.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/EventDispatcher.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/SigilHookOs.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/SigilHookOsIncludes.hpp
		)
install(FILES ${SIGILHOOK_CORE_HEADERS} DESTINATION include/sigilhook)


target_sources(${PROJECT_NAME} PRIVATE
	${PROJECT_SOURCE_DIR}/sources/MemProtector.cpp
	${PROJECT_SOURCE_DIR}/sources/MemAccessor.cpp
	${PROJECT_SOURCE_DIR}/sources/TestEffectTracker.cpp
	${PROJECT_SOURCE_DIR}/sources/StackCanary.cpp
	${PROJECT_SOURCE_DIR}/sources/FBAllocator.cpp
	${PROJECT_SOURCE_DIR}/sources/RangeAllocator.cpp
	${PROJECT_SOURCE_DIR}/sources/ErrorLog.cpp
	${PROJECT_SOURCE_DIR}/sources/UID.cpp
	${PROJECT_SOURCE_DIR}/sources/Misc.cpp
	${PROJECT_SOURCE_DIR}/sources/SigilHookOs.cpp
	)

if(NOT SIGILHOOK_BUILD_DLL)
	target_compile_options(${PROJECT_NAME} PRIVATE
		$<$<BOOL:${UNIX}>:-fpermissive>
	)
endif()

#DisAsm/Zydis
if (SIGILHOOK_USE_EXTERNAL_ZYDIS)
    find_library(ZYDIS_LIBRARY NAMES Zydis)
    find_library(ZYCORE_LIBRARY NAMES Zycore)
    find_path(ZYDIS_INCLUDE_DIR NAMES Zydis/Zydis.h)
    find_path(ZYCORE_INCLUDE_DIR NAMES Zycore/Zycore.h)
    target_link_libraries(${PROJECT_NAME} PUBLIC ${ZYDIS_LIBRARY})
    target_link_libraries(${PROJECT_NAME} PUBLIC ${ZYCORE_LIBRARY})
    target_include_directories(${PROJECT_NAME} PUBLIC ${ZYDIS_INCLUDE_DIR})
    target_include_directories(${PROJECT_NAME} PUBLIC ${ZYCORE_INCLUDE_DIR})
	find_package(zydis REQUIRED)
    target_link_libraries(${PROJECT_NAME} PUBLIC Zydis::Zydis)
else()
    target_link_libraries(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:Zydis>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/zydis/include>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/zydis/dependencies/zycore/include>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/zydis>)
endif()

target_sources(${PROJECT_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/sources/CodeDetour.cpp")
install(FILES ${PROJECT_SOURCE_DIR}/sigilhook/Detour/CodeDetour.hpp DESTINATION include/sigilhook/Detour)
target_sources(${PROJECT_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/sources/ZydisDisassembler.cpp")
install(FILES ${PROJECT_SOURCE_DIR}/sigilhook/ZydisDisassembler.hpp DESTINATION include/sigilhook)

function(link_asmjit)
    if (SIGILHOOK_USE_EXTERNAL_ASMJIT)
		find_package(asmjit CONFIG REQUIRED)
		if(NOT TARGET asmjit::asmjit)
			message(FATAL_ERROR "External AsmJit package does not provide asmjit::asmjit")
		endif()
        target_link_libraries(${PROJECT_NAME} PRIVATE asmjit::asmjit)
    else()
        target_link_libraries(${PROJECT_NAME} PRIVATE $<BUILD_INTERFACE:asmjit>)
        target_include_directories(${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${ASMJIT_SRC}>")
    endif()
endfunction()

#Feature/Detours
if(SIGILHOOK_FEATURE_DETOURS)
    link_asmjit()

    if (SIGILHOOK_USE_EXTERNAL_ASMTK)
		find_package(asmtk CONFIG REQUIRED)
		if(NOT TARGET asmjit::asmtk)
			message(FATAL_ERROR "External AsmTK package does not provide asmjit::asmtk")
		endif()
        target_link_libraries(${PROJECT_NAME} PRIVATE asmjit::asmtk)
    else()
        target_link_libraries(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:asmtk>)
        target_include_directories(${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${ASMTK_SRC}>")
    endif()

	set(SIGILHOOK_DETOUR_HEADERS
		${PROJECT_SOURCE_DIR}/sigilhook/Detour/ADetour.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/Detour/NatDetour.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/Detour/x64Detour.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/Detour/x86Detour.hpp)

	install(FILES ${SIGILHOOK_DETOUR_HEADERS} DESTINATION include/sigilhook/Detour)

	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/sources/ADetour.cpp
		${PROJECT_SOURCE_DIR}/sources/x64Detour.cpp
		${PROJECT_SOURCE_DIR}/sources/x86Detour.cpp)

	# only build tests if making exe
	if(NOT SIGILHOOK_BUILD_DLL)
		if(CMAKE_SIZEOF_VOID_P EQUAL 8) #64-bit
			target_sources(${PROJECT_NAME} PRIVATE
			    ${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestDetourx64.cpp
			    ${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestDetourTranslationx64.cpp
				${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestDetourSchemex64.cpp)
		elseif(CMAKE_SIZEOF_VOID_P EQUAL 4) #32-bit
			target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestDetourx86.cpp)
		endif()
	endif()
endif()

#Feature/Inlinentd
if(SIGILHOOK_FEATURE_INLINENTD)
    link_asmjit()

	install(FILES ${PROJECT_SOURCE_DIR}/sigilhook/Detour/ILCallback.hpp DESTINATION include/sigilhook/Detour)

	target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/sources/ILCallback.cpp)

	# only build tests if making exe
	if(NOT SIGILHOOK_BUILD_DLL)
		if(CMAKE_SIZEOF_VOID_P EQUAL 8)
			target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestDetourNoTDx64.cpp)
		elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
			target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestDetourNoTDx86.cpp)
		endif()
	endif()
endif()

#Feature/Exception
if(SIGILHOOK_FEATURE_EXCEPTION)
    set(SIGILHOOK_EXCEPTION_HEADERS
        ${PROJECT_SOURCE_DIR}/sigilhook/Exceptions/AVehHook.hpp
        ${PROJECT_SOURCE_DIR}/sigilhook/Exceptions/BreakPointHook.hpp
        ${PROJECT_SOURCE_DIR}/sigilhook/Exceptions/HWBreakPointHook.hpp)
    install(FILES ${SIGILHOOK_EXCEPTION_HEADERS} DESTINATION include/sigilhook/Exceptions)

    target_sources(${PROJECT_NAME} PRIVATE
        ${PROJECT_SOURCE_DIR}/sources/AVehHook.cpp
        ${PROJECT_SOURCE_DIR}/sources/BreakPointHook.cpp
        ${PROJECT_SOURCE_DIR}/sources/HWBreakPointHook.cpp)

    # only build tests if making exe
    if(NOT SIGILHOOK_BUILD_DLL)
        target_sources(${PROJECT_NAME} PRIVATE
            ${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestBreakpointHook.cpp
            ${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestHWBreakpointHook.cpp)
    endif()
endif()

#Feature/PE
if(SIGILHOOK_FEATURE_PE)
	set(SIGILHOOK_PE_HEADERS
		${PROJECT_SOURCE_DIR}/sigilhook/PE/EatHook.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/PE/IatHook.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/PE/PEB.hpp)
	install(FILES ${SIGILHOOK_PE_HEADERS} DESTINATION include/sigilhook/PE)

	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/sources/EatHook.cpp
		${PROJECT_SOURCE_DIR}/sources/IatHook.cpp)

	# only build tests if making exe
	if(NOT SIGILHOOK_BUILD_DLL)
		target_sources(${PROJECT_NAME} PRIVATE
			${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestEatHook.cpp
			${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestIatHook.cpp)
	endif()
endif()


#Feature/Virtuals
if(SIGILHOOK_FEATURE_VIRTUALS)
	set(SIGILHOOK_VIRTUAL_HEADERS
		${PROJECT_SOURCE_DIR}/sigilhook/Virtuals/VTableSwapHook.hpp
		${PROJECT_SOURCE_DIR}/sigilhook/Virtuals/VFuncSwapHook.hpp)
	install(FILES ${SIGILHOOK_VIRTUAL_HEADERS} DESTINATION include/sigilhook/Virtuals)

	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/sources/VTableSwapHook.cpp
		${PROJECT_SOURCE_DIR}/sources/VFuncSwapHook.cpp)

	# only build tests if making exe
	if(NOT SIGILHOOK_BUILD_DLL)
		target_sources(${PROJECT_NAME} PRIVATE
			${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestVTableSwapHook.cpp
			
			${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestVFuncSwapHook.cpp)
	endif()
endif()


#Tests
if(NOT SIGILHOOK_BUILD_DLL)
	target_compile_definitions(${PROJECT_NAME} PRIVATE SIGILHOOK_DIAGNOSTICS)
	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/MainTests.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestDisassembler.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/${SIGILHOOK_OS}/TestMemProtector.cpp)

	enable_testing()
	add_test(NAME SigilHookCoreTests COMMAND ${PROJECT_NAME})
	set_tests_properties(SigilHookCoreTests PROPERTIES TIMEOUT 60)
endif()


#
# Install
#

configure_package_config_file(
		"${LOWERCASE_PROJECT_NAME}-config.cmake.in"
		"${LOWERCASE_PROJECT_NAME}-config.cmake"
	INSTALL_DESTINATION
        "lib/${PROJECT_NAME}"
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/${LOWERCASE_PROJECT_NAME}-config.cmake"
    DESTINATION
        "lib/${PROJECT_NAME}"
)

set(SIGILHOOK_INSTALL_TARGETS ${PROJECT_NAME})
if(SIGILHOOK_FEATURE_ANGELSCRIPT AND NOT SIGILHOOK_USE_EXTERNAL_ANGELSCRIPT)
    list(APPEND SIGILHOOK_INSTALL_TARGETS angelscript)
    install(FILES ${PROJECT_SOURCE_DIR}/third_party/angelscript/sdk/angelscript/include/angelscript.h DESTINATION include)
endif()

install(TARGETS ${SIGILHOOK_INSTALL_TARGETS}
    EXPORT ${PROJECT_NAME}-targets
    RUNTIME DESTINATION "bin"
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib"
    INCLUDES DESTINATION "include"
)

install(
    EXPORT
        ${PROJECT_NAME}-targets
    NAMESPACE
        ${PROJECT_NAME}::
    DESTINATION
        "lib/${PROJECT_NAME}"
)
if(SIGILHOOK_FEATURE_ANGELSCRIPT)
    target_link_libraries(${PROJECT_NAME} PUBLIC ${SIGILHOOK_ANGELSCRIPT_TARGET})
    target_compile_definitions(${PROJECT_NAME} PUBLIC SIGILHOOK_HAS_ANGELSCRIPT=1)
endif()

if(SIGILHOOK_FEATURE_ANGELSCRIPT AND SIGILHOOK_BUILD_ANGELSCRIPT_SMOKE_TEST)
    add_executable(AngelScriptSmokeTest Examples/AngelScriptSmokeTest/main.cpp)
    set_target_properties(AngelScriptSmokeTest PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
    target_link_libraries(AngelScriptSmokeTest PRIVATE ${SIGILHOOK_ANGELSCRIPT_TARGET})

    enable_testing()
    add_test(NAME AngelScriptSmokeTest COMMAND AngelScriptSmokeTest)
endif()
if(MSVC AND SIGILHOOK_FEATURE_ANGELSCRIPT AND SIGILHOOK_BUILD_ANGELSCRIPT_SMOKE_TEST)
    if(SIGILHOOK_BUILD_STATIC_RUNTIME)
        set_target_properties(AngelScriptSmokeTest PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set_target_properties(AngelScriptSmokeTest PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()
endif()
include(${PROJECT_SOURCE_DIR}/cmake/SigilHookRuntime.cmake)
