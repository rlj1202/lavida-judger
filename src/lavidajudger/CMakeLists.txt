set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

include(FetchContent)

FetchContent_Declare(
    sandboxed-api
    GIT_REPOSITORY https://github.com/google/sandboxed-api
    GIT_TAG        75c708162218ac286cf212f84a910e86a7b63b19
)

FetchContent_MakeAvailable(sandboxed-api)

add_library(lavidajudger STATIC
    lib.cpp
    ../../include/lavidajudger/lavidajudger.h
)
target_include_directories(lavidajudger PUBLIC
    ../../include
)
target_link_libraries(lavidajudger PRIVATE
    seccomp
    rt
    Threads::Threads

    absl::memory
    sandbox2::bpf_helper
    sandbox2::sandbox2
    sapi::base

    # sapi::flags
    # sapi::logging
    # sapi::runfiles
)
