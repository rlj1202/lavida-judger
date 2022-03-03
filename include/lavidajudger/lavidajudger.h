#ifndef H_LAVIDAJUDGER
#define H_LAVIDAJUDGER

#include <string>

namespace lavidajudger {

enum class judgetype {
    INOUT_FIXED, // normal type
    IN_FIXED, // special judge
    OUT_FIXED,
    DYNAMIC, // interactive type
};

struct judgeoptions {
    judgetype type;

    char* execpath;
    char* inputFilePath;
    char* outputFilePath;
    char* errFilePath;
    char* validaterPath;

    unsigned int cpulimit; // in seconds
    unsigned int reallimit; // in seconds
    unsigned int memlimit; // in bytes
};

enum class graderesult {
    CORRECT, // 맞았습니다
    WRONG, // 틀렸습니다
    CPU_TIME_LIMIT, // 시간 초과
    SEGMENTATION_FAULT, // 메모리 초과
    RUNTIME_ERROR, // 런타임 에러
    BAD_SYSTEM_CALL, // 시스템 콜
    // 출력 형식 오류
    // 출력 초과
};

struct judgeresults {
    unsigned int cputime; // in micro seconds (1 / 1e6 seconds)
    unsigned int realtime; // in micro seconds (1 / 1e6 seconds)
    unsigned int mem; // in bytes

    int exitcode; // process exit code when success
    int signal; // process exit signal when failure

    graderesult result;
};

enum class judgestatus {
    SUCCESS,
    INVALID_ARGUMENT,
    PIPE_FAIL,
    FORK_FAIL,
    WAIT_FAIL,
    RLIMIT_FAIL,
    SECCOMP_FAIL,
    EXECVE_FAIL,
    VALIDATE_FAIL,
    NO_INPUT,
};

/**
 * 
 * @param options
 * @param results
 * @return judgestatus - SUCCESS on normal operation.
 * INVALID_ARGUMENT when either options or results is null.
 * EXECVE_FAIL when failed to execute given file.
 */
judgestatus judge(const judgeoptions* options, judgeresults* results);

}

#endif
