#include <stdio.h>
#include <string.h>

#include <string>
#include <memory>
#include <stdexcept>

#include <CLI/CLI.hpp>
#include <CLI/App.hpp>

#include "lavidajudger/lavidajudger.h"

template<typename ... Args>
std::string string_format(const std::string& format, Args ... args) {
    // Extra space for '\0'
    int size_s = std::snprintf(nullptr, 0, format.c_str(), args ...) + 1;
    if( size_s <= 0 ){ throw std::runtime_error( "Error during formatting." ); }

    auto size = static_cast<size_t>( size_s );
    auto buf = std::make_unique<char[]>( size );
    std::snprintf( buf.get(), size, format.c_str(), args ... );

    // We don't want the '\0' inside
    return std::string( buf.get(), buf.get() + size - 1 );
}

int main(int argc, const char* const argv[]) {
    CLI::App app("lavida-executor");
    app.allow_extras();

    int cpuLimit = 1;
    int realLimit = 1;
    int memLimit = 1024*1024*256;

    std::string execFilePath;
    std::string inputFilePath;
    std::string outputFilePath;
    std::string validaterFilePath;

    bool displayJson = true;

    app.add_option("--exec-path", execFilePath, "Executable file path.")
        ->check(CLI::ExistingFile);
    app.add_option("--input-path", inputFilePath, "Input file path.")
        ->check(CLI::ExistingFile);
    app.add_option("--output-path", outputFilePath, "Output file path.")
        ->check(CLI::ExistingFile);
    app.add_option("--validator-path", validaterFilePath,
            "Validator executable file path.")
        ->check(CLI::ExistingFile);

    app.add_option("--cpu-limit", cpuLimit,
        string_format("CPU time limit in seconds. Default is %d second.",
            cpuLimit))
        ->check(CLI::NonNegativeNumber);

    app.add_option("--real-limit", realLimit,
        string_format("Real time limit in seconds. Default is %d second.",
            realLimit))
        ->check(CLI::NonNegativeNumber);

    app.add_option("--mem-limit", memLimit,
        string_format("Memory limit in bytes. Default is %d MB. (%d bytes)",
            memLimit / 1024 / 1024, memLimit))
        ->check(CLI::NonNegativeNumber);

    app.add_flag("--json,!--no-json", displayJson,
        string_format("Display results as json output. Default is %s.",
            displayJson ? "true" : "false"));

    CLI11_PARSE(app, argc, argv);

    using namespace lavidajudger;

    judgeoptions options;
    judgeresults results;

    options.type = judgetype::INOUT_FIXED;

    // CAUTION: unsafe const to non-const conversion.
    options.execpath = execFilePath.empty() ? nullptr : (char*) execFilePath.c_str();
    options.inputFilePath = inputFilePath.empty() ? nullptr : (char*) inputFilePath.c_str();
    options.outputFilePath = outputFilePath.empty() ? nullptr : (char*) outputFilePath.c_str();
    options.errFilePath = nullptr;
    options.validaterPath = validaterFilePath.empty() ? nullptr : (char*) validaterFilePath.c_str();

    options.cpulimit = cpuLimit;
    options.reallimit = realLimit;
    options.memlimit = memLimit;

    judgestatus status = judge(&options, &results);

    if (displayJson) {
        printf("{\n");
        if (status == judgestatus::SUCCESS) {
            printf("\t\"cputime\": %d,\n", results.cputime);
            printf("\t\"realtime\": %d,\n", results.realtime);
            printf("\t\"memory\": %d,\n", results.mem);
            printf("\t\"exitcode\": %d,\n", results.exitcode);
            printf("\t\"signal\": %d,\n", results.signal);
            printf("\t\"graderesult\": %d,\n", (int) results.result);
        } else {
            printf("\t\"error\": %d,\n", (int) status);
        }
        printf("}\n");
    } else {
        if (status == judgestatus::SUCCESS) {
            printf("cputime: %.4f secs (%d us)\n", results.cputime / 1e6, results.cputime);
            printf("realtime: %.4f secs (%d us)\n", results.realtime / 1e6, results.realtime);
            printf("memory: %.2f MB\n", results.mem / 1024.0f / 1024.0f);

            printf("exitcode: %d", results.exitcode);
            if (results.exitcode != 0)
                printf(" (%s)", strsignal(results.signal));
            printf("\n");

            printf("signal: %d\n", results.signal);
 
            printf("graderesult: %d (", (int) results.result);
            if (results.result == graderesult::CORRECT) printf("CORRECT");
            if (results.result == graderesult::WRONG) printf("WRONG");
            if (results.result == graderesult::CPU_TIME_LIMIT) printf("CPU TIME LIMIT");
            if (results.result == graderesult::SEGMENTATION_FAULT) printf("SEG FAULT");
            if (results.result == graderesult::RUNTIME_ERROR) printf("RUNTIME ERROR");
            if (results.result == graderesult::BAD_SYSTEM_CALL) printf("BAD SYSTEM CALL");
            printf(")\n");
        } else {
            printf("error: %d\n", (int) status);
        }
    }

    return 0;
}
