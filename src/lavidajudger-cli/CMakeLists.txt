include(FetchContent)

FetchContent_Declare(
    jsoncpp
    GIT_REPOSITORY https://github.com/open-source-parsers/jsoncpp
    GIT_TAG        8190e061bc2d95da37479a638aa2c9e483e58ec6
)

FetchContent_Declare(
    cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11
    GIT_TAG        faea921e4004af91763b8fde905de3baf24d3945
)

FetchContent_MakeAvailable(jsoncpp cli11)

add_executable(lavidajudger-cli main.cpp)
target_link_libraries(lavidajudger-cli PRIVATE
    lavidajudger
    CLI11::CLI11
    jsoncpp_static
)

install(TARGETS lavidajudger-cli DESTINATION bin)
