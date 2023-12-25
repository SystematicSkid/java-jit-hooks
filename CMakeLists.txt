cmake_minimum_required( VERSION 3.20 FATAL_ERROR )
project( java-tests )

set( CMAKE_CXX_STANDARD 20 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

# Enable MASM
enable_language( ASM_MASM )

# Ensure MASM compiler is available
if( NOT CMAKE_ASM_MASM_COMPILER )
    message( FATAL_ERROR "MASM compiler not found" )
endif()


# Glob ./src/*.cpp and ./src/*.asm into SOURCES variable, recursively
set( SOURCES src/main.cpp src/hde/hde64.cpp src/utility/hook.cpp src/utility/naked_hook.asm  )
# Includes ./include
include_directories( include )

# Find JNI library
find_package( JNI REQUIRED )

# Include jni headers
include_directories( ${JNI_INCLUDE_DIRS} )

# Create shared library from sources
add_library( java-tests SHARED ${SOURCES} )

# Link jvm
target_link_libraries( java-tests ${JNI_LIBRARIES} )