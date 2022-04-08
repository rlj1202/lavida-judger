#include <stdio.h>
#include <string.h>

#include <string>
#include <memory>
#include <stdexcept>
#include <vector>

#include <CLI/CLI.hpp>
#include <CLI/App.hpp>

#include "lavidajudger/lavidajudger.h"

template<typename ... Args>
std::string string_format(const std::string& format, Args... args) {
    // Extra space for '\0'
    int size_s = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
    if (size_s <= 0) { throw std::runtime_error( "Error during formatting." ); }

    auto size = static_cast<size_t>(size_s);
    auto buf = std::make_unique<char[]>(size);
    std::snprintf(buf.get(), size, format.c_str(), args...);

    // We don't want the '\0' inside
    return std::string(buf.get(), buf.get() + size - 1);
}

int main(int argc, const char* const argv[]) {
    CLI::App app("lavida-executor");
    app.allow_extras();

    int cpuLimit = 1;
    int realLimit = 1;
    int memLimit = 1024*1024*256;

    std::string execFilePath;
    std::vector<std::string> execArgs;
    std::string inputFilePath;
    std::string outputFilePath;
    std::string validaterFilePath;

    bool displayJson = true;

    app.add_option("--exec-path", execFilePath, "Executable file path.");
    app.add_option("--exec-args", execArgs, "Arguments to executable.");
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

    std::vector<char*> execArgsCstr;
    execArgsCstr.push_back(execFilePath.empty() ? nullptr : (char*) execFilePath.c_str());
    for (std::string& str : execArgs) {
        execArgsCstr.push_back((char*) str.c_str());
    }
    execArgsCstr.push_back(nullptr);

    judgeoptions options;
    judgeinfo info;

    options.type = judgetype::INOUT_FIXED;

    // CAUTION: unsafe const to non-const conversion
    //          due to the absence of const keyword of the old C code.
    options.execpath = execFilePath.empty() ? nullptr : (char*) execFilePath.c_str();
    options.execArgs = execArgsCstr.data();
    options.inputFilePath = inputFilePath.empty() ? nullptr : (char*) inputFilePath.c_str();
    options.outputFilePath = outputFilePath.empty() ? nullptr : (char*) outputFilePath.c_str();
    options.errFilePath = nullptr;
    options.validaterPath = validaterFilePath.empty() ? nullptr : (char*) validaterFilePath.c_str();

    options.cpulimit = cpuLimit;
    options.reallimit = realLimit;
    options.memlimit = memLimit;

    judgestatus status = judge(&options, &info);

    if (status != judgestatus::SUCCESS) {
        char const* msg = "Unknown Error.";

        switch (status) {
        case judgestatus::INVALID_ARGUMENT:
            msg = "Invalid argument.";
            break;
        case judgestatus::PIPE_FAIL:
            msg = "Pipe fail.";
            break;
        case judgestatus::FORK_FAIL:
            msg = "Fork fail.";
            break;
        case judgestatus::WAIT_FAIL:
            msg = "Wait fail.";
            break;
        case judgestatus::RLIMIT_FAIL:
            msg = "Rlimit fail.";
            break;
        case judgestatus::SECCOMP_FAIL:
            msg = "Seccomp fail.";
            break;
        case judgestatus::EXECVE_FAIL:
            msg = "Execve fail.";
            break;
        case judgestatus::VALIDATE_FAIL:
            msg = "Validate fail.";
            break;
        case judgestatus::NO_INPUT:
            msg = "No input.";
            break;
        case judgestatus::SHM_FAIL:
            msg = "Shared memory fail.";
            break;
        case judgestatus::MAP_FAIL:
            msg = "Mmap fail.";
            break;
        case judgestatus::TRUNCATE_FAIL:
            msg = "Truncate fail.";
            break;

        default:
            break;
        }

        dprintf(fileno(stderr), "Judge status : %s\n", msg);

        return EXIT_FAILURE;
    }

    if (displayJson) {
        printf("{\n");
        printf("\t\"cputime\": %d,\n", info.cputime);
        printf("\t\"realtime\": %d,\n", info.realtime);
        printf("\t\"memory\": %d,\n", info.mem);
        printf("\t\"exitcode\": %d,\n", info.exitcode);
        printf("\t\"signal\": %d,\n", info.signal);
        printf("\t\"judgeresult\": %d\n", (int) info.result);
        printf("}\n");
    } else {
        printf("cputime: %.4f secs (%d us)\n", info.cputime / 1e6, info.cputime);
        printf("realtime: %.4f secs (%d us)\n", info.realtime / 1e6, info.realtime);
        printf("memory: %.2f MB\n", info.mem / 1024.0f / 1024.0f);

        printf("exitcode: %d", info.exitcode);
        if (info.exitcode != 0)
            printf(" (%s)", strsignal(info.signal));
        printf("\n");

        printf("signal: %d\n", info.signal);
 
        printf("judgeresult: %d (", (int) info.result);
        if (info.result == judgeresult::CORRECT) printf("CORRECT");
        if (info.result == judgeresult::WRONG) printf("WRONG");
        if (info.result == judgeresult::CPU_TIME_LIMIT) printf("CPU TIME LIMIT");
        if (info.result == judgeresult::SEGMENTATION_FAULT) printf("SEG FAULT");
        if (info.result == judgeresult::RUNTIME_ERROR) printf("RUNTIME ERROR");
        if (info.result == judgeresult::BAD_SYSTEM_CALL) printf("BAD SYSTEM CALL");
        if (info.result == judgeresult::PRESENTATION_ERROR) printf("PRESENTATION ERROR");
        if (info.result == judgeresult::PRESENTATION_EXCEED) printf("PRESENTATION EXCEED");
        printf(")\n");
    }

    return 0;
}
