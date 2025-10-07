cmake_minimum_required(VERSION 3.11)

project(twofish LANGUAGES C CXX)

# 启用CTest
enable_testing()

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(twofish
        src/twofish.cpp
)

target_include_directories(twofish PUBLIC
        includes
)

# 添加twofish_ctest目标
add_executable(twofish_ctest
        test/twofish_ctest.cpp
)

target_link_libraries(twofish_ctest
        twofish
)
target_include_directories(twofish_ctest PUBLIC
        includes
)

# 注册CTest测试
add_test(NAME twofish_ctest COMMAND twofish_ctest)
