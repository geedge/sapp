
# Using autorevision.sh to generate version information

set(__SOURCE_AUTORESIVISION ${CMAKE_SOURCE_DIR}/autorevision.sh)
set(__AUTORESIVISION ${CMAKE_BINARY_DIR}/autorevision.sh)
set(__VERSION_CACHE ${CMAKE_SOURCE_DIR}/version.txt)
set(__VERSION_CONFIG ${CMAKE_BINARY_DIR}/version.cmake)

file(COPY ${__SOURCE_AUTORESIVISION} DESTINATION ${CMAKE_BINARY_DIR}
	FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
	WORLD_READ WORLD_EXECUTE)

# execute autorevision.sh to generate version information
execute_process(COMMAND ${__AUTORESIVISION} -t cmake -o ${__VERSION_CACHE} 
				OUTPUT_FILE ${__VERSION_CONFIG} ERROR_QUIET)
include(${__VERSION_CONFIG})

# extract major, minor, patch version from git tag
string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" SAPP_VERSION_MAJOR "${VCS_TAG}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" SAPP_VERSION_MINOR "${VCS_TAG}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" SAPP_VERSION_PATCH "${VCS_TAG}")

if(NOT SAPP_VERSION_MAJOR)
    set(SAPP_VERSION_MAJOR 3)
endif()

if(NOT SAPP_VERSION_MINOR)
    set(SAPP_VERSION_MINOR 0)
endif()

if(NOT SAPP_VERSION_PATCH)
    set(SAPP_VERSION_PATCH 0)
endif()

set(SAPP_VERSION "${SAPP_VERSION_MAJOR}.${SAPP_VERSION_MINOR}.${SAPP_VERSION_PATCH}")
set(SAPP_VERSION_BUILD "${VCS_SHORT_HASH}")

# print information
message(STATUS "Sapp Version: ${SAPP_VERSION}-${SAPP_VERSION_BUILD}")

set(SAPP_GIT_VERSION "${SAPP_VERSION}-${SAPP_VERSION_BUILD}")
add_definitions(-DGITVER=\"${SAPP_GIT_VERSION}\")
