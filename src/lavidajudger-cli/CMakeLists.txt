add_executable(lavidajudger-cli main.cpp)
target_link_libraries(lavidajudger-cli
    PUBLIC lavidajudger
    PUBLIC CLI11::CLI11
    )

install(TARGETS lavidajudger-cli DESTINATION bin)
