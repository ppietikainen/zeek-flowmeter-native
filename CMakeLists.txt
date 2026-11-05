cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginFlowMeter)

foreach(_caf_target CAF::core CAF::io CAF::net)
    if(NOT TARGET ${_caf_target})
        add_library(${_caf_target} INTERFACE IMPORTED)
    endif()
endforeach()

include(ZeekPlugin)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The script-side version comes from VERSION, so there is one place to bump.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" FLOWMETER_VERSION LIMIT_COUNT 1)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION")
configure_file(scripts/version.zeek.in ${CMAKE_CURRENT_SOURCE_DIR}/scripts/version.zeek @ONLY)

add_compile_definitions(FLOWMETER_VERSION="${FLOWMETER_VERSION}")

zeek_plugin_begin(Flow Meter ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc src/FlowStats.cc)
zeek_plugin_dist_files(README COPYING VERSION)
zeek_plugin_scripts(scripts/__load__.zeek scripts/main.zeek scripts/version.zeek.in)
zeek_plugin_end()
