#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/signal.h>

// libseccomp
#include <seccomp.h>

// void cpusigHandler(int signo) {
//     printf("cpusigHandler: %d\n", signo);
// }

int workerProcess(int* ptc, int* ctp) {
    unsigned long bytes = 8 * 1024 * 1024LL;
    rlim_t timeLimit = 1; // in seconds
    char filePath[] = "./src/dummy/dummy";

    /*************************************************************************** 
     * Limit the resource
     * https://linux.die.net/man/2/setrlimit
     **************************************************************************/
    struct rlimit rlim;
    rlim.rlim_cur = bytes;
    rlim.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_AS, &rlim) == -1) { // virtual memory (Address Space)
        printf("Failed to limit memory resource of worker process: errno = %d\n", errno);
        return -1;
    }

    rlim.rlim_cur = rlim.rlim_max = timeLimit; // in seconds
    rlim.rlim_max++; // SIGXCPU generated after the cpu time reaches the soft
                     // limit first. So advance the hard limit one second ahead.
    if (setrlimit(RLIMIT_CPU, &rlim) == -1) { // cpu time
        printf("Failed to limit cpu resource of worker process: errno = %d\n", errno);
        return -1;
    }

    // struct sigaction cpusig = { 0 };
    // sigemptyset(&cpusig.sa_mask);
    // cpusig.sa_flags = 0;
    // cpusig.sa_handler = cpusigHandler;
    // if (sigaction(SIGXCPU, &cpusig, NULL) == -1) {
    //     printf("Failed to sigaction\n");
    //     return -1;
    // }
    // if (sigaction(SIGSEGV, &cpusig, NULL) == -1) {
    //     printf("Failed to sigaction\n");
    //     return -1;
    // }

    /*************************************************************************** 
     * Connect pipe to stdout, stderr and stdin
     **************************************************************************/
    // 0 = READ
    // 1 = WRITE
    close(ptc[1]);
    close(ctp[0]);
    dup2(ctp[1], STDOUT_FILENO);
    dup2(ctp[1], STDERR_FILENO);
    dup2(ptc[0], STDIN_FILENO);

    /*************************************************************************** 
     * Set seccomp profile
     **************************************************************************/
    int rc = 0;
    scmp_filter_ctx ctx = NULL;

    char* argv[] = { filePath, NULL };

    // ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    ctx = seccomp_init(SCMP_ACT_KILL);

    if (ctx == NULL)
        return ENOMEM;

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
    if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 3,
        SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t) filePath),
        SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t) argv),
        SCMP_A2(SCMP_CMP_EQ, (scmp_datum_t) NULL));
    // if (rc == 0) rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
    //     SCMP_A0(SCMP_CMP_EQ, 4));

    if (rc == 0) rc = seccomp_load(ctx);

    /*************************************************************************** 
     * Execute program
     **************************************************************************/
    if (rc == 0) {
        int result;
        if ((result = execve(filePath, argv, NULL)) == -1) {
            printf("Failed to execve: errno = %d\n", errno);
        }
    }

    if (rc == 0) seccomp_release(ctx);

    printf("Failed to seccomp\n");

    return (rc < 0 ? -rc : rc);
}

int main() {
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    printf("cwd = %s\n", cwd);

    int parentToChild[2];
    int childToParent[2];
    pipe(parentToChild);
    pipe(childToParent);

    pid_t workerPid = fork();

    if (workerPid == -1) {
        printf("failed to fork\n");

        return -1;
    } else if (workerPid == 0) { // child process, worker process
        int result = workerProcess(parentToChild, childToParent);
        printf("child result = %d\n", result);
        return result;
    }

    // parent process
    close(parentToChild[0]);
    close(childToParent[1]);

    dprintf(parentToChild[1], "123\n");
    close(parentToChild[1]);

    int statusCode;
    rusage rscUsage;
    int waitPid = wait4(workerPid, &statusCode, 0, &rscUsage);

    if (waitPid == -1) {
        return -1;
    }

    if (WIFEXITED(statusCode)) {
        printf("Child process %d successfully terminated: %d\n", waitPid, WEXITSTATUS(statusCode));

        char buf[1024];
        int readlen;
        printf("\"");
        while ((readlen = read(childToParent[0], buf, sizeof(buf) - 1)) > 0) {
            buf[readlen] = 0;
            printf("%s", buf);
        }
        printf("\"");
    } else if (WIFSIGNALED(statusCode)) {
        int signal = WTERMSIG(statusCode);
        char* signalDesc = strsignal(signal);
        printf("Child process %d terminated with signal: %d, %s\n", waitPid, signal, signalDesc);

        if (signal == SIGXCPU) {
            printf("CPU_TIME_LIMIT\n");
        } else if (signal == SIGSEGV) {
            printf("SEG FAULT\n");
        } else if (signal == SIGSYS) {
            printf("BAD SYSTEM CALL\n");
        }

        printf("mem = %.2f MB\n", rscUsage.ru_maxrss / 1024.0f);
        printf("utime = %d, %.4f secs\n", (int) rscUsage.ru_utime.tv_sec, rscUsage.ru_utime.tv_usec / 1000000.0f);
        printf("stime = %d, %.4f secs\n", (int) rscUsage.ru_stime.tv_sec, rscUsage.ru_stime.tv_usec / 1000000.0f);
    }

    return 0;
}
