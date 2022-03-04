#include "lavidajudger/lavidajudger.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/signal.h>

#include <thread>
#include <chrono>
#include <sstream>

// libseccomp
#include <seccomp.h>

namespace lavidajudger {

int setSeccompRules(scmp_filter_ctx &ctx) {
    int rc = 0;

    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    // if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
    //     SCMP_A0(SCMP_CMP_EQ, STDIN_FILENO));
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
        SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
        SCMP_A0(SCMP_CMP_EQ, STDERR_FILENO));
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    // if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
    //     SCMP_A0(SCMP_CMP_EQ, 4));

    return rc;
}

// returns exit code
int workerProcess(const judgeoptions* options, judgestatus* status) {
    *status = judgestatus::SUCCESS;

    /*************************************************************************** 
     * Limit the resource
     * https://linux.die.net/man/2/setrlimit
     **************************************************************************/
    struct rlimit rlim;
    rlim.rlim_cur = options->memlimit;
    rlim.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_AS, &rlim) == -1) { // virtual memory (Address Space)
        *status = judgestatus::RLIMIT_FAIL; // TODO: extra info in errno
        return EXIT_FAILURE;
    }

    rlim.rlim_cur = rlim.rlim_max = options->cpulimit; // in seconds
    rlim.rlim_max++; // SIGXCPU generated after the cpu time reaches the soft
                     // limit first. So advance the hard limit one second ahead.
    if (setrlimit(RLIMIT_CPU, &rlim) == -1) { // cpu time
        *status = judgestatus::RLIMIT_FAIL; // TODO: extra info in errno
        return EXIT_FAILURE;
    }

    /*************************************************************************** 
     * Set seccomp profile
     **************************************************************************/
    int rc = 0;
    scmp_filter_ctx ctx = NULL;

    char* const argv[] = { options->execpath, NULL };

    // ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    ctx = seccomp_init(SCMP_ACT_KILL);

    if (ctx == NULL) {
        *status = judgestatus::SECCOMP_FAIL; // TODO: extra info in errno
        return EXIT_FAILURE;
    }

    setSeccompRules(ctx);

    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 3,
        SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t) options->execpath),
        SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t) argv),
        SCMP_A2(SCMP_CMP_EQ, (scmp_datum_t) NULL));

    if (rc == 0) rc = seccomp_load(ctx);

    /*************************************************************************** 
     * Execute program
     **************************************************************************/
    if (rc == 0) {
        int result;
        if ((result = execve(options->execpath, argv, NULL)) == -1) {
            *status = judgestatus::EXECVE_FAIL; // TODO: extra info in errno
            return EXIT_FAILURE;
        }
    }

    if (rc == 0) seccomp_release(ctx);

    *status = judgestatus::SECCOMP_FAIL;
    return EXIT_FAILURE;
}

// returns exit code
int validateProcess(const judgeoptions* options) {
    if (options->validaterPath == NULL) return 0;

    char* const argv[] = {
        options->inputFilePath,
        options->outputFilePath,
        NULL,
        };

    int result;
    if ((result = execve(options->validaterPath, argv, NULL)) == -1) {
        // TODO:
        return EXIT_FAILURE;
    }

    return 0;
}

judgestatus judge(const judgeoptions* options, judgeresults* results) {
    // check arguments
    if (options == nullptr) return judgestatus::INVALID_ARGUMENT;
    if (results == nullptr) return judgestatus::INVALID_ARGUMENT;

    // init judgeresults struct
    results->cputime = 0;
    results->mem = 0;

    results->exitcode = 0;
    results->signal = 0;

    // creating pipes
    int childOutput[2];
    int childError[2];
    int childJudgeStatus[2];

    int validaterOutput[2];
    int validaterError[2];

    if (pipe(childOutput) == -1) return judgestatus::PIPE_FAIL;
    if (pipe(childError) == -1) return judgestatus::PIPE_FAIL;
    if (pipe(childJudgeStatus) == -1) return judgestatus::PIPE_FAIL;

    if (pipe(validaterOutput) == -1) return judgestatus::PIPE_FAIL;
    if (pipe(validaterError) == -1) return judgestatus::PIPE_FAIL;

    // create sub processes
    pid_t validaterPid = fork();

    if (validaterPid == -1) {
        return judgestatus::FORK_FAIL;
    } else if (validaterPid == 0) {
        close(childOutput[1]);
        close(childError[0]);
        close(childError[1]);
        close(childJudgeStatus[0]);
        close(childJudgeStatus[1]);
        close(validaterOutput[0]);
        close(validaterError[0]);

        dup2(childOutput[0], STDIN_FILENO);
        dup2(validaterOutput[1], STDOUT_FILENO);
        dup2(validaterError[1], STDERR_FILENO);

        int exitcode = validateProcess(options);

        close(childOutput[0]);
        close(validaterOutput[1]);
        close(validaterError[1]);

        exit(exitcode);
    }

    pid_t workerPid = fork();

    if (workerPid == -1) {
        return judgestatus::FORK_FAIL;
    } else if (workerPid == 0) { // child process, workerProcess
        close(childOutput[0]);
        close(childError[0]);
        close(validaterOutput[1]);

        // connect stdin, stdout and stderr
        dup2(childOutput[1], STDOUT_FILENO);
        dup2(childError[1], STDERR_FILENO);

        if (options->inputFilePath != NULL) {
            FILE* inputFile;
            if ((inputFile = fopen(options->inputFilePath, "r")) != NULL) {
                dup2(fileno(inputFile), STDIN_FILENO);
            }
        } else if (options->validaterPath != NULL) {
            dup2(validaterOutput[0], STDIN_FILENO);
        } else {
            judgestatus status = judgestatus::NO_INPUT;
            close(childJudgeStatus[0]);
            write(childJudgeStatus[1], &status, sizeof(status));
            close(childJudgeStatus[1]);
            
            exit(EXIT_FAILURE);
        }

        // execute worker
        judgestatus status;
        int exitcode = workerProcess(options, &status);

        // pass judge status
        close(childJudgeStatus[0]);
        write(childJudgeStatus[1], &status, sizeof(status));
        close(childJudgeStatus[1]);

        // clean up pipes
        close(childOutput[1]);
        close(childError[1]);
        close(validaterOutput[0]);

        exit(exitcode);
    }

    // parent process

    close(childOutput[1]);
    close(childError[1]);
    close(childJudgeStatus[1]);
    close(validaterOutput[1]);
    close(validaterError[1]);

    using namespace std::chrono;
    high_resolution_clock::time_point timeStart = high_resolution_clock::now();

    std::thread timerThread([&]() -> void {
        sleep(options->reallimit);

        kill(workerPid, SIGXCPU);
        kill(validaterPid, SIGXCPU);
    });
    timerThread.detach();

    // wait for processes
    int validaterStatusCode;

    int workerStatusCode;
    rusage workerRscUsage;

    if (waitpid(validaterPid, &validaterStatusCode, 0) == -1) {
        return judgestatus::WAIT_FAIL;
    }
    if (wait4(workerPid, &workerStatusCode, 0, &workerRscUsage) == -1) {
        return judgestatus::WAIT_FAIL;
    }

    high_resolution_clock::time_point timeEnd = high_resolution_clock::now();

    // validate result
    bool validateResult = false;

    if (options->validaterPath == NULL && options->outputFilePath != NULL) {
        std::stringstream outputFileContent;
        std::stringstream stdoutResult;

        FILE* outputFile;
        if ((outputFile = fopen(options->outputFilePath, "r")) != NULL) {
        }
 
        char buf[1024];
        int readlen;

        while ((readlen = read(fileno(outputFile), buf, sizeof(buf))) > 0) {
            outputFileContent.write(buf, readlen);
        }
        while ((readlen = read(childOutput[0], buf, sizeof(buf))) > 0) {
            stdoutResult.write(buf, readlen);
        }
 
        validateResult = outputFileContent.str().compare(stdoutResult.str()) == 0;
    }

    judgestatus status = judgestatus::SUCCESS;

    if (WIFEXITED(validaterStatusCode)) {
        int exitcode = WEXITSTATUS(validaterStatusCode);
        validateResult = exitcode == EXIT_SUCCESS;

        if (exitcode != EXIT_SUCCESS) status = judgestatus::VALIDATE_FAIL;
    } else {
        status = judgestatus::VALIDATE_FAIL;
    }

    if (WIFEXITED(workerStatusCode)) {
        results->exitcode = WEXITSTATUS(workerStatusCode);

        close(childJudgeStatus[1]);
        if (read(childJudgeStatus[0], &status, sizeof(status)) == 0) {
            status = judgestatus::SUCCESS;
        }
        close(childJudgeStatus[0]);

        results->result = validateResult ? graderesult::CORRECT : graderesult::WRONG;
    } else {
        results->exitcode = EXIT_FAILURE;
        results->signal = WTERMSIG(workerStatusCode);

        results->result = graderesult::RUNTIME_ERROR;

        if (results->signal == SIGXCPU) {
            results->result = graderesult::CPU_TIME_LIMIT;
        } else if (results->signal == SIGSEGV) {
            results->result = graderesult::SEGMENTATION_FAULT;
        } else if (results->signal == SIGSYS) {
            results->result = graderesult::BAD_SYSTEM_CALL;
        }
    }

    results->cputime =
        workerRscUsage.ru_utime.tv_sec * 1000000 + workerRscUsage.ru_utime.tv_usec;

    results->realtime =
        duration_cast<microseconds>(timeEnd - timeStart).count();

    results->mem =
        workerRscUsage.ru_maxrss * 1024; // ru_maxrss = KB unit

    return status;
}

}
