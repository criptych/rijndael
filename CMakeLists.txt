CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(rijndael C CXX)

INCLUDE(CheckCCompilerFlag)
INCLUDE(CheckCXXCompilerFlag)

MACRO(ADD_C_COMPILER_FLAG FLAGS FLAG)
    STRING(MAKE_C_IDENTIFIER "${FLAG}" ID)
    CHECK_C_COMPILER_FLAG("${FLAG}" "CFLAG_${ID}")
    IF(CFLAG_${ID})
        SET(${FLAGS} "${${FLAGS}} ${FLAG}")
    ENDIF()
ENDMACRO()

MACRO(ADD_CXX_COMPILER_FLAG FLAGS FLAG)
    STRING(MAKE_C_IDENTIFIER "${FLAG}" ID)
    CHECK_CXX_COMPILER_FLAG("${FLAG}" "CXXFLAG_${ID}")
    IF(CXXFLAG_${ID})
        SET(${FLAGS} "${${FLAGS}} ${FLAG}")
    ENDIF()
ENDMACRO()

# MSVC options
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/Wall")          # Enable all warnings
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/WX")            # Treat warnings as errors
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/Za")            # Disable language extensions
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/Zi")            # Generate debugging information (PDB)
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/arch:SSE")      # Enable SSE opcodes
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/arch:SSE2")     # Enable SSE2 opcodes

ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "/Wall")          # Enable all warnings
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "/WX")            # Treat warnings as errors
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "/Za")            # Disable language extensions
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "/Zi")            # Generate debugging information (PDB)
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "/arch:SSE")      # Enable SSE opcodes
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "/arch:SSE2")     # Enable SSE2 opcodes

# GCC/Clang options
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Wall")          # Enable all (actually most) warnings
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Weverything")   # (Clang) Enable ALL warnings
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Wextra")        # (GCC) Enable more (all?) warnings
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Wpedantic")     # (GCC) Disable language extensions
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Werror")        # Treat warnings as errors
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Wno-error=pedantic") # ... except pedantic warnings
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-std=c99")       # Enable C99
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-msse")          # Enable SSE opcodes
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-msse2")         # Enable SSE2 opcodes

ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-Wall")          # Enable all (actually most) warnings
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-Weverything")   # (Clang) Enable ALL warnings
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-Wextra")        # (GCC) Enable more (all?) warnings
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-Wpedantic")     # (GCC) Disable language extensions
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-Werror")        # Treat warnings as errors
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-Wno-error=pedantic") # ... except pedantic warnings
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-std=c++0x")     # Enable C++11 (older GCC versions)
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-std=c++11")     # Enable C++11
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-std=c++14")     # Enable C++14 (if available)
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-std=c++17")     # Enable C++17 (if available)
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-msse")          # Enable SSE opcodes
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-msse2")         # Enable SSE2 opcodes

ADD_LIBRARY(rijndael rijndael.h rijndael.c)
TARGET_INCLUDE_DIRECTORIES(rijndael PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

FILE(GLOB ECB_TESTS ${CMAKE_CURRENT_BINARY_DIR}/tests/ECB*.cpp)
FILE(GLOB CBC_TESTS ${CMAKE_CURRENT_BINARY_DIR}/tests/CBC*.cpp)
FILE(GLOB OFB_TESTS ${CMAKE_CURRENT_BINARY_DIR}/tests/OFB*.cpp)
FILE(GLOB CFB_TESTS ${CMAKE_CURRENT_BINARY_DIR}/tests/CFB*.cpp)

ADD_EXECUTABLE(selftest catch.hpp testmain.cpp selftest.cpp)
ADD_EXECUTABLE(ecbtest catch.hpp testmain.cpp ${ECB_TESTS})
ADD_EXECUTABLE(cbctest catch.hpp testmain.cpp ${CBC_TESTS})
ADD_EXECUTABLE(ofbtest catch.hpp testmain.cpp ${OFB_TESTS})
ADD_EXECUTABLE(cfbtest catch.hpp testmain.cpp ${CFB_TESTS})

TARGET_LINK_LIBRARIES(selftest rijndael)
TARGET_LINK_LIBRARIES(ecbtest rijndael)
TARGET_LINK_LIBRARIES(cbctest rijndael)
TARGET_LINK_LIBRARIES(ofbtest rijndael)
TARGET_LINK_LIBRARIES(cfbtest rijndael)

ADD_CUSTOM_TARGET(gentests
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gentests.py
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/gentests.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

ADD_DEPENDENCIES(ecbtest gentests)
ADD_DEPENDENCIES(cbctest gentests)
ADD_DEPENDENCIES(ofbtest gentests)
ADD_DEPENDENCIES(cfbtest gentests)

ADD_CUSTOM_TARGET(doselftest COMMAND selftest -r xml -o selftest.xml)
ADD_CUSTOM_TARGET(doecbtest COMMAND ecbtest -r xml -o ecbtest.xml)
ADD_CUSTOM_TARGET(docbctest COMMAND cbctest -r xml -o cbctest.xml)
ADD_CUSTOM_TARGET(doofbtest COMMAND ofbtest -r xml -o ofbtest.xml)
ADD_CUSTOM_TARGET(docfbtest COMMAND cfbtest -r xml -o cfbtest.xml)

