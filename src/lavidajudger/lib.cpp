#include "lavidajudger/lavidajudger.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
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

    // TODO: for python3, temporarily.
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);

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

    // char* const argv[] = { options->execpath, NULL };
    char* const* argv = options->execArgs;

    // whitelist method
    ctx = seccomp_init(SCMP_ACT_KILL);
    // ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));

    if (ctx == NULL) {
        *status = judgestatus::SECCOMP_FAIL; // TODO: extra info is in errno
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
int validateProcess(const judgeoptions* options, judgestatus* status) {
    if (options->validaterPath == NULL) return 0;

    char* const argv[] = {
        options->inputFilePath,
        options->outputFilePath,
        NULL,
        };

    int result;
    if ((result = execve(options->validaterPath, argv, NULL)) == -1) {
        *status = judgestatus::EXECVE_FAIL;
        return EXIT_FAILURE;
    }

    return 0;
}

const char SHARED_MEM_NAME[] = "/lavidajudger";

struct shared_mem {
    judgestatus worker_status;
    judgestatus validater_status;
};

judgestatus judge(const judgeoptions* options, judgeinfo* info) {
    // check arguments
    if (options == nullptr) return judgestatus::INVALID_ARGUMENT;
    if (info == nullptr) return judgestatus::INVALID_ARGUMENT;

    // init judgeresults struct
    info->cputime = 0;
    info->mem = 0;

    info->exitcode = 0;
    info->signal = 0;

    // create shared memory
    int sharedMemFd = shm_open(SHARED_MEM_NAME, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (sharedMemFd == -1) {
        return judgestatus::SHM_FAIL;
    }
    if (ftruncate(sharedMemFd, sizeof(shared_mem)) == -1) {
        return judgestatus::TRUNCATE_FAIL;
    }
    shared_mem* shared_obj = (shared_mem*) mmap(NULL, sizeof(shared_mem), PROT_READ | PROT_WRITE, MAP_SHARED, sharedMemFd, 0);
    if (shared_obj == MAP_FAILED) {
        return judgestatus::MAP_FAIL;
    }
    shared_obj->worker_status = judgestatus::SUCCESS;
    shared_obj->validater_status = judgestatus::SUCCESS;

    // creating pipes
    int childOutput[2];
    int childError[2];

    int validaterOutput[2];
    int validaterError[2];

    if (pipe(childOutput) == -1) return judgestatus::PIPE_FAIL;
    if (pipe(childError) == -1) return judgestatus::PIPE_FAIL;

    if (pipe(validaterOutput) == -1) return judgestatus::PIPE_FAIL;
    if (pipe(validaterError) == -1) return judgestatus::PIPE_FAIL;

    // create sub processes

    // validater process
    pid_t validaterPid = fork();

    if (validaterPid == -1) {
        return judgestatus::FORK_FAIL;
    } else if (validaterPid == 0) {
        dup2(childOutput[0], STDIN_FILENO);
        dup2(validaterOutput[1], STDOUT_FILENO);
        dup2(validaterError[1], STDERR_FILENO);

        close(childOutput[0]);
        close(childOutput[1]);
        close(childError[0]);
        close(childError[1]);
        close(validaterOutput[0]);
        close(validaterOutput[1]);
        close(validaterError[0]);
        close(validaterError[1]);

        int exitcode = validateProcess(options, &shared_obj->validater_status);

        exit(exitcode);
    }

    // worker process
    pid_t workerPid = fork();

    if (workerPid == -1) {
        return judgestatus::FORK_FAIL;
    } else if (workerPid == 0) { // child process, workerProcess
        int childInput = 0;

        if (options->inputFilePath != NULL) {
            FILE* inputFile;
            if ((inputFile = fopen(options->inputFilePath, "r")) != NULL) {
                childInput = fileno(inputFile);
            }
        } else if (options->validaterPath != NULL) {
            childInput = validaterOutput[0];
        } else {
            shared_obj->worker_status = judgestatus::NO_INPUT;
            
            exit(EXIT_FAILURE);
        }

        // connect stdin, stdout and stderr
        dup2(childInput, STDIN_FILENO);
        dup2(childOutput[1], STDOUT_FILENO);
        dup2(childError[1], STDERR_FILENO);

        // clean up useless fds
        close(childOutput[0]);
        close(childOutput[1]);
        close(childError[0]);
        close(childError[1]);
        close(validaterOutput[1]);
        close(validaterOutput[0]);
        close(validaterError[0]);
        close(validaterError[1]);

        // execute worker
        int exitcode = workerProcess(options, &shared_obj->worker_status);

        exit(exitcode);
    }

    // parent process

    close(childOutput[1]);
    close(childError[1]);
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

        fprintf(stderr, "stdout: \"%s\"\n", stdoutResult.str().c_str());
 
        validateResult = outputFileContent.str().compare(stdoutResult.str()) == 0;
    }

    judgestatus status = judgestatus::SUCCESS;

    if (options->validaterPath != NULL) {
        if (WIFEXITED(validaterStatusCode)) {
            int exitcode = WEXITSTATUS(validaterStatusCode);
            validateResult = exitcode == EXIT_SUCCESS;
 
            if (exitcode != EXIT_SUCCESS) status = judgestatus::VALIDATE_FAIL;
        } else {
            status = judgestatus::VALIDATE_FAIL;
        }
    }

    if (WIFEXITED(workerStatusCode)) {
        info->exitcode = WEXITSTATUS(workerStatusCode);

        status = shared_obj->worker_status;

        info->result = validateResult ? judgeresult::CORRECT : judgeresult::WRONG;
    } else {
        info->exitcode = EXIT_FAILURE;
        info->signal = WTERMSIG(workerStatusCode);

        info->result = judgeresult::RUNTIME_ERROR;

        if (info->signal == SIGXCPU) {
            info->result = judgeresult::CPU_TIME_LIMIT;
        } else if (info->signal == SIGSEGV) {
            info->result = judgeresult::SEGMENTATION_FAULT;
        } else if (info->signal == SIGSYS) {
            info->result = judgeresult::BAD_SYSTEM_CALL;
        }
    }

    info->cputime =
        workerRscUsage.ru_utime.tv_sec * 1000000 + workerRscUsage.ru_utime.tv_usec;

    info->realtime =
        duration_cast<microseconds>(timeEnd - timeStart).count();

    info->mem =
        workerRscUsage.ru_maxrss * 1024; // ru_maxrss = KB unit
    
    // clean up shared memory
    shm_unlink(SHARED_MEM_NAME);
    close(sharedMemFd);

    return status;
}

}
