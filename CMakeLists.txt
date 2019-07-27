# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME toyasn1 )

set( PROTO_OPT )

set( EXT_ASN_FILE_LIST
)

set( ASN_FILE_LIST
	${PROTOCOL_NAME}.asn
)

set( EXTRA_DIST
	${ASN_FILE_LIST}
	packet-${PROTOCOL_NAME}-template.c
	packet-${PROTOCOL_NAME}-template.h
	${PROTOCOL_NAME}.cnf
)

set( SRC_FILES
	${EXTRA_DIST}
	${EXT_ASN_FILE_LIST}
)

set( A2W_FLAGS -b -L )

set(A2W_OUTPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR})

ASN2WRS()


add_custom_command(
    OUTPUT  ${CMAKE_CURRENT_SOURCE_DIR}/packet-${PROTOCOL_NAME}.c
	COMMAND echo ""
)


include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(${PROTOCOL_NAME} 0 1 1 0)

set(DISSECTOR_SRC
	${CMAKE_CURRENT_SOURCE_DIR}/packet-${PROTOCOL_NAME}.c
)

set(DISSECTOR_SUPPORT_SRC
	
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})


register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

add_plugin_library(${PROTOCOL_NAME} epan)

target_link_libraries(${PROTOCOL_NAME} epan)


install_plugin(${PROTOCOL_NAME} epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  ${PROTOCOL_NAME}
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_SUPPORT_SRC}
	  ${DISSECTOR_HEADERS}
)
