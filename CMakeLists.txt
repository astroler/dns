CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
#AUX_SOURCE_DIRECTORY(. DIR_SRCS)
#ADD_EXECUTABLE(vind ${DIR_SRCS})
ADD_DEFINITIONS(-DCDNDEBUG)
PROJECT(vind7)
EXECUTE_PROCESS(
    COMMAND sh version.sh
    )
SET(MALLOC_CHECK_ 0)#vind.c)

INCLUDE_DIRECTORIES(
    ${PROJECT_BINARY_DIR}
    ${PROJECT_SOURCE_DIR}/include/
    ${PROJECT_SOURCE_DIR}/./
    ${PROJECT_SOURCE_DIR}/db
    ${PROJECT_SOURCE_DIR}/utils
    ${PROJECT_SOURCE_DIR}/engine
    /opt/cdn/include/
)
SET(SRC_LIST )#vind.c)
aux_source_directory("./" SRC_LIST)
aux_source_directory("./engine" SRC_LIST)
aux_source_directory("./utils" SRC_LIST)
aux_source_directory("./db" SRC_LIST)

ADD_DEFINITIONS("-g -O0")
LINK_DIRECTORIES("/opt/cdn/lib")
SET(CMAKE_C_FLAGS "-DCDNDEBUG")
ADD_EXECUTABLE(vind7 ${SRC_LIST})
TARGET_LINK_LIBRARIES(vind7 libevent.a libgdsl.a libhiredis.a libthreads.a pthread rt)
#TARGET_LINK_LIBRARIES(vind -L/opt/cdn/lib/libhiredis.a -L/opt/cdn/lib/libevent.a -L/opt/cdn/lib/libgdsl.a -L/opt/cdn/lib/libhiredis.a -L./lib/libthreads.a pthread)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
#SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

#ADD_SUBDIRECTORY (db)
#ADD_SUBDIRECTORY (utils)
#ADD_SUBDIRECTORY (engine)
