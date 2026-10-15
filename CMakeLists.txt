cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginMPLSLogging)

include(ZeekPlugin)

zeek_plugin_begin(Zeek MPLSLogging ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc src/MPLSLogging.cc)
zeek_plugin_dist_files(README.md CHANGES LICENSE NOTICE.txt VERSION)
zeek_plugin_scripts(scripts/__load__.zeek)
zeek_plugin_end()

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
# Enable AddressSanitizer and LeakSanitizer in Debug builds
if (CMAKE_BUILD_TYPE MATCHES "Debug")
    message(STATUS "Enabling AddressSanitizer (ASan)")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

endif ()
