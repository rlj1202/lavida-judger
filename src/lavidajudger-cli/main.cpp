#include <iostream>
#include <string>
#include <memory>
#include <stdexcept>
#include <vector>

#include "lavidajudger/lavidajudger.h"

#include "CLI/CLI.hpp"
#include "CLI/App.hpp"

#include "json/json.h"

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

    lavidajudger::judgetype type{lavidajudger::judgetype::NORMAL};

    std::string execFilePath;
    std::vector<std::string> execArgs;

    std::string inputFilePath;
    std::string outputFilePath;

    std::string validatorFilePath;
    std::vector<std::string> validatorArgs;

    std::string policy;

    std::map<std::string, lavidajudger::judgetype> typeMapping{
        { "normal", lavidajudger::judgetype::NORMAL },
        { "special", lavidajudger::judgetype::SPECIAL },
        { "interactive", lavidajudger::judgetype::INTERACTIVE },
    };

    app.add_option("--type", type, "Judging type")
        ->transform(CLI::CheckedTransformer(typeMapping, CLI::ignore_case));

    app.add_option("--exec-path", execFilePath, "Executable file path.")
        ->required();
    app.add_option("--exec-args", execArgs, "Arguments to executable.");

    app.add_option("--input-path", inputFilePath, "Input file path.")
        ->check(CLI::ExistingFile);
    app.add_option("--output-path", outputFilePath, "Output file path.")
        ->check(CLI::ExistingFile);

    app.add_option(
        "--validator-path", validatorFilePath,
        "Validator executable file path.")
        ->check(CLI::ExistingFile);
    app.add_option(
        "--validator-args", validatorArgs,
        "Arguments to validator.");

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

    app.add_option("--policy", policy,
        "Policy name which is used to sandbox executable.");

    CLI11_PARSE(app, argc, argv);

    // Config
    using namespace lavidajudger;

    if (type == judgetype::NORMAL) {
        if (inputFilePath.empty() || outputFilePath.empty()) {
            std::cout << "Normal judge needs input file and output file.";
            std::cout << std::endl;
            std::cout << "Run with --help for more information." << std::endl;
            return EXIT_FAILURE;
        }
    } else if (type == judgetype::SPECIAL) {
        if (inputFilePath.empty() || validatorFilePath.empty()) {
            std::cout << "Special judge needs input file and validator path.";
            std::cout << std::endl;
            std::cout << "Run with --help for more information." << std::endl;
            return EXIT_FAILURE;
        }
    } else if (type == judgetype::INTERACTIVE) {
        if (validatorFilePath.empty()) {
            std::cout << "Interactive judge needs validator path." << std::endl;
            std::cout << "Run with --help for more information." << std::endl;
            return EXIT_FAILURE;
        }
    }

    std::vector<char*> execArgsCstr;
    execArgsCstr.push_back(execFilePath.empty() ? nullptr : (char*) execFilePath.c_str());
    for (std::string& str : execArgs) {
        execArgsCstr.push_back((char*) str.c_str());
    }
    execArgsCstr.push_back(nullptr);

    judgeoptions options;
    options.type = judgetype::NORMAL;

    // CAUTION: unsafe const to non-const conversion
    //          due to the absence of const keyword of the old C code.
    options.execpath = execFilePath.empty() ? nullptr : (char*) execFilePath.c_str();
    options.execArgs = execArgsCstr.data();

    options.inputFilePath = inputFilePath.empty() ? nullptr : (char*) inputFilePath.c_str();
    options.outputFilePath = outputFilePath.empty() ? nullptr : (char*) outputFilePath.c_str();
    options.errFilePath = nullptr;

    options.validatorPath = validatorFilePath.empty() ? nullptr : (char*) validatorFilePath.c_str();
    options.validatorArgs = nullptr;

    options.cpulimit = cpuLimit;
    options.reallimit = realLimit;
    options.memlimit = memLimit;

    // Judging
    judgeinfo info;
    judgestatus status = judge(&options, &info);

    // Print result in json format
    Json::Value root;

    root["judgestatus"] = (int) status;
    root["judgestatus_msg"] = judgeStatusToString(status);

    if (status == judgestatus::SUCCESS) {
        root["cputime"] = info.cputime;
        root["realtime"] = info.realtime;
        root["memory"] = info.mem;
 
        root["exitcode"] = info.exitcode;
 
        root["signal"] = info.signal;
        if (info.signal) root["signal_msg"] = strsignal(info.signal);
 
        root["judgeresult"] = (int) info.result;
        root["judgeresult_msg"] = judgeResultToString(info.result);
    }

    Json::StreamWriterBuilder builder;
    const std::string json_file = Json::writeString(builder, root);
    std::cout << json_file << std::endl;

    return 0;
}
