cmake_minimum_required(VERSION 3.3.0)
cmake_policy(SET CMP0074 NEW)
if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW) 
endif()

project(test_sigilhook)

find_package(SigilHook CONFIG REQUIRED)

set(CMAKE_CXX_FLAGS "/std:c++latest ${CMAKE_CXX_FLAGS}")

add_executable(test_sigilhook main.cpp)
set_property(TARGET test_sigilhook PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
target_link_libraries(test_sigilhook PRIVATE SigilHook::SigilHook)
