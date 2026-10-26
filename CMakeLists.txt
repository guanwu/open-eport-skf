# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com>
cmake_minimum_required(VERSION 3.20)
project(eportskf LANGUAGES C)

set(EPORTSKF_VERSION "0.0.0" CACHE STRING "Version recorded in the installed CMake package configuration")

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Media and protocol sources shared by every supported platform.
set(EPORTSKF_COMMON_SOURCES
    src/api.c
    src/certificate.c
    src/crypto.c
    src/hid.c
    src/pcsc.c
)

# Each platform provides the same two transport interfaces, so the rest of the
# library builds without platform conditionals.
if(WIN32)
    set(EPORTSKF_PLATFORM_SOURCES
        src/hid_windows.c
        src/pcsc_windows.c
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(EPORTSKF_PLATFORM_SOURCES
        src/hid_linux.c
        src/pcsc_linux.c
    )
else()
    message(FATAL_ERROR "eportskf supports Windows and Linux")
endif()

add_library(eportskf_library SHARED ${EPORTSKF_COMMON_SOURCES} ${EPORTSKF_PLATFORM_SOURCES})
add_library(eportskf_static STATIC ${EPORTSKF_COMMON_SOURCES} ${EPORTSKF_PLATFORM_SOURCES})
add_library(eportskf::eportskf ALIAS eportskf_library)
add_library(eportskf::eportskf_static ALIAS eportskf_static)
set_target_properties(eportskf_library PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    DEFINE_SYMBOL EPORTSKF_BUILDING_LIBRARY
    EXPORT_NAME eportskf
    OUTPUT_NAME eportskf
)
set_target_properties(eportskf_static PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    EXPORT_NAME eportskf_static
    OUTPUT_NAME eportskf_static
    POSITION_INDEPENDENT_CODE ON
)
# A consumer of the static library must not import symbols from a DLL, so the
# definition travels with the target.
target_compile_definitions(eportskf_static PUBLIC EPORTSKF_STATIC)

# Both libraries build the same sources with the same warnings and include
# paths; only the linkage and the platform libraries differ.
foreach(target eportskf_library eportskf_static)
    target_include_directories(${target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /utf-8)
        target_compile_definitions(${target} PRIVATE _WIN32_WINNT=0x0601 WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endforeach()

if(MSVC)
    target_link_libraries(eportskf_library PRIVATE hid setupapi winscard)
    target_link_libraries(eportskf_static PUBLIC hid setupapi winscard)
else()
    # Only the EPORTSKF_API declarations are exported from the Linux shared
    # library; the static library keeps every symbol.
    set_target_properties(eportskf_library PROPERTIES C_VISIBILITY_PRESET hidden)
    target_link_libraries(eportskf_library PRIVATE ${CMAKE_DL_LIBS})
    target_link_libraries(eportskf_static PUBLIC ${CMAKE_DL_LIBS})
endif()

add_executable(eportskf_cli cli/eportskf.c)
set_target_properties(eportskf_cli PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    OUTPUT_NAME eportskf
)
target_link_libraries(eportskf_cli PRIVATE eportskf_library)
if(MSVC)
    target_compile_options(eportskf_cli PRIVATE /W4 /WX /utf-8)
    target_compile_definitions(eportskf_cli PRIVATE _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0601 WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
    target_link_libraries(eportskf_cli PRIVATE shell32)
else()
    target_compile_options(eportskf_cli PRIVATE -Wall -Wextra -Wpedantic -Werror)
    set_target_properties(eportskf_cli PROPERTIES INSTALL_RPATH "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")
endif()

install(TARGETS eportskf_library eportskf_static
    EXPORT eportskfTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(TARGETS eportskf_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/eportskf.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/eportskf)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/eportskf)

configure_package_config_file(
    cmake/eportskfConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/eportskfConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/eportskf
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/eportskfConfigVersion.cmake
    VERSION ${EPORTSKF_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(EXPORT eportskfTargets
    FILE eportskfTargets.cmake
    NAMESPACE eportskf::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/eportskf
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/eportskfConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/eportskfConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/eportskf
)
