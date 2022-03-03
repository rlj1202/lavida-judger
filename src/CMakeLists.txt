add_subdirectory(dummy)
add_subdirectory(special)

add_subdirectory(lavidajudger)
add_subdirectory(lavidajudger-cli)

add_executable(lavida-judger main.cpp)
target_link_libraries(lavida-judger seccomp)
