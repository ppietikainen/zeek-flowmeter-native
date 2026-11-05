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

zeek_plugin_begin(Flow Meter ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc src/FlowStats.cc)
zeek_plugin_dist_files(README COPYING VERSION)
zeek_plugin_scripts(scripts/__load__.zeek scripts/main.zeek)
zeek_plugin_end()
