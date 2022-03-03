set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

add_library(lavidajudger STATIC lib.cpp ../../include/lavidajudger/lavidajudger.h)
target_include_directories(lavidajudger PUBLIC ../../include)
target_link_libraries(lavidajudger seccomp Threads::Threads)
