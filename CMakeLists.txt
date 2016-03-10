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

ADD_CUSTOM_COMMAND(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/tests/ecbtests.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/tests/cbctests.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/tests/ofbtests.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/tests/cfb8tests.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/tests/cfb128tests.cpp
    COMMAND
        python ${CMAKE_CURRENT_SOURCE_DIR}/gentests.py
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/gentests.py
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}
)

ADD_EXECUTABLE(selftest catch.hpp testmain.cpp selftest.cpp)
ADD_EXECUTABLE(ecbtests catch.hpp testmain.cpp ${CMAKE_CURRENT_BINARY_DIR}/tests/ecbtests.cpp)
ADD_EXECUTABLE(cbctests catch.hpp testmain.cpp ${CMAKE_CURRENT_BINARY_DIR}/tests/cbctests.cpp)
ADD_EXECUTABLE(ofbtests catch.hpp testmain.cpp ${CMAKE_CURRENT_BINARY_DIR}/tests/ofbtests.cpp)
ADD_EXECUTABLE(cfb8tests catch.hpp testmain.cpp ${CMAKE_CURRENT_BINARY_DIR}/tests/cfb8tests.cpp)
ADD_EXECUTABLE(cfb128tests catch.hpp testmain.cpp ${CMAKE_CURRENT_BINARY_DIR}/tests/cfb128tests.cpp)
ADD_EXECUTABLE(alltests catch.hpp testmain.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tests/ecbtests.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tests/cbctests.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tests/ofbtests.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tests/cfb8tests.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tests/cfb128tests.cpp
)

TARGET_LINK_LIBRARIES(selftest rijndael)
TARGET_LINK_LIBRARIES(ecbtests rijndael)
TARGET_LINK_LIBRARIES(cbctests rijndael)
TARGET_LINK_LIBRARIES(ofbtests rijndael)
TARGET_LINK_LIBRARIES(cfb8tests rijndael)
TARGET_LINK_LIBRARIES(cfb128tests rijndael)
TARGET_LINK_LIBRARIES(alltests rijndael)

ENABLE_TESTING()

ADD_TEST(NAME doselftest COMMAND selftest -r xml -o selftest.xml)
ADD_TEST(NAME doecbtests COMMAND ecbtests -r xml -o ecbtests.xml)
ADD_TEST(NAME docbctests COMMAND cbctests -r xml -o cbctests.xml)
ADD_TEST(NAME doofbtests COMMAND ofbtests -r xml -o ofbtests.xml)
ADD_TEST(NAME docfb8tests COMMAND cfb8tests -r xml -o cfb8tests.xml)
ADD_TEST(NAME docfb128tests COMMAND cfb128tests -r xml -o cfb128tests.xml)
ADD_TEST(NAME doalltests COMMAND alltests -r xml -o alltests.xml)

ADD_TEST(NAME regression COMMAND alltests ~[cfb8]~[mct],[cfb8]~[mmt]~[mct])
