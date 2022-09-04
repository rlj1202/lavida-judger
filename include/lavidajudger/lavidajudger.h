#ifndef H_LAVIDAJUDGER
#define H_LAVIDAJUDGER

#include <string>

namespace lavidajudger {

/**
 * @struct judgetype
 * @brief Type of judging.
 */
enum class judgetype {
    NORMAL,
    SPECIAL,
    INTERACTIVE,
};

/**
 * @struct judgeoptions
 * @brief Options to judge.
 */
struct judgeoptions {
    judgetype type;

    char* execpath;
    char** execArgs;

    char* inputFilePath;
    char* outputFilePath;
    char* errFilePath;

    char* validatorPath;
    char** validatorArgs;

    char* policy_name;

    unsigned int cpulimit;  // in seconds
    unsigned int reallimit; // in seconds
    unsigned int memlimit;  // in bytes
};

/**
 * @enum judgeresult
 * @brief Judge result of given executable.
 */
enum class judgeresult {
    CORRECT,             // 맞았습니다
    WRONG,               // 틀렸습니다
    CPU_TIME_LIMIT,      // 시간 초과
    SEGMENTATION_FAULT,  // 메모리 초과
    RUNTIME_ERROR,       // 런타임 에러
    BAD_SYSTEM_CALL,     // 시스템 콜
    PRESENTATION_ERROR,  // 출력 형식 오류, codeforces의 경우 해당 케이스는 없고
                         // 그냥 오류로 처리한다.
    PRESENTATION_EXCEED, // 출력 초과
};

/**
 * @struct judgeinfo
 * @brief Contains informations of judging.
 */
struct judgeinfo {
    unsigned int cputime;  // in micro seconds (1 / 1e6 seconds)
    unsigned int realtime; // in micro seconds (1 / 1e6 seconds)
    unsigned int mem;      // in bytes

    int exitcode; // process exit code when success
    int signal;   // process exit signal when failure

    judgeresult result;
};

/**
 * @enum judgestatus
 * @brief Status of judging, which indicates all the operations to check
 *        given executable is valid are done properly.
 */
enum class judgestatus {
    SUCCESS,          // All operations are done properly.
    INVALID_ARGUMENT, // Given arguments are not valid.
    PIPE_FAIL,        // `pipe` system call.
    FORK_FAIL,        // `fork` system call.
    WAIT_FAIL,        // `wait` system call.
    EXECVE_FAIL,      // `execve` system call.
    RLIMIT_FAIL,      // Resource limit operations failed.
    SECCOMP_FAIL,     // Seccomp operations failed.
    VALIDATE_FAIL,    // Given validater was not called properly.
    NO_INPUT,         // There is no valid input source to check
                      //     given executable is valid.
    SHM_FAIL,         // Shared memory system call.
    MAP_FAIL,         // `mmap` system call.
    TRUNCATE_FAIL,    // `ftruncate` system call.
    OPEN_FAIL,        // Open file call.
};

std::string judgeResultToString(judgeresult result);
std::string judgeStatusToString(judgestatus status);

/**
 * @brief Judge an executable file.
 * @param options
 * @param info
 * @return judgestatus - SUCCESS on normal operation. Otherwise, returns
 * another value which indicates why the operations are not done all the way.
 */
judgestatus judge(const judgeoptions* options, judgeinfo* info);

}

#endif
