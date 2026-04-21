/*
 * engine.c - Supervised Multi-Container Runtime
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

/* Standardized SEND macro for Task 2 IPC */
#define SEND(fd, buf, len)  do { ssize_t _s = write((fd),(buf),(len)); if(_s < 0) {} } while(0)

#define STACK_SIZE           (1024 * 1024)   /* 1 MiB stack per container  */
#define CONTAINER_ID_LEN      32
#define CONTROL_PATH          "/tmp/mini_runtime.sock"
#define LOG_DIR              "logs"
#define CONTROL_MESSAGE_LEN  512
#define CHILD_COMMAND_LEN    256
#define LOG_CHUNK_SIZE       4096
#define LOG_BUFFER_CAPACITY  16
#define DEFAULT_SOFT_LIMIT   (40UL << 20)   /* 40 MiB */
#define DEFAULT_HARD_LIMIT   (64UL << 20)   /* 64 MiB */
#define MONITOR_DEVICE       "/dev/container_monitor"

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED,
    CONTAINER_HARD_LIMIT_KILLED
} container_state_t;

typedef struct container_record {
    char              id[CONTAINER_ID_LEN];
    pid_t              host_pid;
    time_t            started_at;
    container_state_t state;
    unsigned long      soft_limit_bytes;
    unsigned long      hard_limit_bytes;
    int                exit_code;
    int                exit_signal;
    int                stop_requested;
    char              log_path[PATH_MAX];
    int                pipe_read_fd;
    struct container_record *next;
} container_record_t;

typedef struct {
    char   container_id[CONTAINER_ID_LEN];
    size_t length;
    char   data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t          items[LOG_BUFFER_CAPACITY];
    size_t          head;
    size_t          tail;
    size_t          count;
    int              shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char           container_id[CONTAINER_ID_LEN];
    char           rootfs[PATH_MAX];
    char           command[CHILD_COMMAND_LEN];
    unsigned long  soft_limit_bytes;
    unsigned long  hard_limit_bytes;
    int            nice_value;
} control_request_t;

typedef struct {
    int  status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int  nice_value;
    int  log_write_fd;
} child_config_t;

typedef struct {
    int                server_fd;
    int                monitor_fd;
    volatile int       should_stop;
    pthread_t          logger_thread;
    bounded_buffer_t  log_buffer;
    pthread_mutex_t    metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

typedef struct {
    supervisor_ctx_t *ctx;
    char              container_id[CONTAINER_ID_LEN];
    int                pipe_read_fd;
} producer_args_t;

static supervisor_ctx_t *g_ctx = NULL;

static int send_control_request(const control_request_t *req);

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag, const char *value, unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;
    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }
    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req, int argc, char *argv[], int start_index)
{
    for (int i = start_index; i < argc; i += 2) {
        if (i + 1 >= argc) return -1;
        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i+1], &req->soft_limit_bytes) != 0) return -1;
        } else if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i+1], &req->hard_limit_bytes) != 0) return -1;
        } else if (strcmp(argv[i], "--nice") == 0) {
            req->nice_value = atoi(argv[i+1]);
        }
    }
    return 0;
}

static const char *state_to_string(container_state_t s)
{
    switch (s) {
    case CONTAINER_STARTING: return "starting";
    case CONTAINER_RUNNING:  return "running";
    case CONTAINER_STOPPED:  return "stopped";
    case CONTAINER_KILLED:   return "killed";
    case CONTAINER_EXITED:   return "exited";
    case CONTAINER_HARD_LIMIT_KILLED: return "hard_limit_killed";
    default: return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *b)
{
    memset(b, 0, sizeof(*b));
    pthread_mutex_init(&b->mutex, NULL);
    pthread_cond_init(&b->not_empty, NULL);
    pthread_cond_init(&b->not_full, NULL);
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *b)
{
    pthread_cond_destroy(&b->not_full);
    pthread_cond_destroy(&b->not_empty);
    pthread_mutex_destroy(&b->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *b)
{
    pthread_mutex_lock(&b->mutex);
    b->shutting_down = 1;
    pthread_cond_broadcast(&b->not_empty);
    pthread_cond_broadcast(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
}

int bounded_buffer_push(bounded_buffer_t *b, const log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == LOG_BUFFER_CAPACITY && !b->shutting_down)
        pthread_cond_wait(&b->not_full, &b->mutex);
    if (b->shutting_down) {
        pthread_mutex_unlock(&b->mutex);
        return -1;
    }
    b->items[b->tail] = *item;
    b->tail = (b->tail + 1) % LOG_BUFFER_CAPACITY;
    b->count++;
    pthread_cond_signal(&b->not_empty);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

int bounded_buffer_pop(bounded_buffer_t *b, log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == 0 && !b->shutting_down)
        pthread_cond_wait(&b->not_empty, &b->mutex);
    if (b->count == 0) {
        pthread_mutex_unlock(&b->mutex);
        return 1;
    }
    *item = b->items[b->head];
    b->head = (b->head + 1) % LOG_BUFFER_CAPACITY;
    b->count--;
    pthread_cond_signal(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);
        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            ssize_t n = write(fd, item.data, item.length);
            if (n < 0) perror("log write");
            close(fd);
        }
    }
    return NULL;
}

static void *producer_thread(void *arg)
{
    producer_args_t *pa = (producer_args_t *)arg;
    supervisor_ctx_t *ctx = pa->ctx;
    int fd = pa->pipe_read_fd;
    char cid[CONTAINER_ID_LEN];
    memset(cid, 0, sizeof(cid));
    snprintf(cid, sizeof(cid), "%s", pa->container_id);
    free(pa);

    log_item_t item;
    ssize_t n;
    while ((n = read(fd, item.data, LOG_CHUNK_SIZE - 1)) > 0) {
        item.data[n] = '\0';
        item.length  = (size_t)n;
        memset(item.container_id, 0, sizeof(item.container_id));
        snprintf(item.container_id, sizeof(item.container_id), "%s", cid);
        if (bounded_buffer_push(&ctx->log_buffer, &item) != 0) break;
    }
    close(fd);
    return NULL;
}

int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;
    if (dup2(cfg->log_write_fd, STDOUT_FILENO) < 0) return 1;
    if (dup2(cfg->log_write_fd, STDERR_FILENO) < 0) return 1;
    close(cfg->log_write_fd);
    sethostname(cfg->id, strlen(cfg->id));
    char proc_path[PATH_MAX + 64];
    snprintf(proc_path, sizeof(proc_path), "%s/proc", cfg->rootfs);
    mkdir(proc_path, 0555);
    if (mount("proc", proc_path, "proc", 0, NULL) < 0) perror("mount proc");
    if (chroot(cfg->rootfs) < 0) return 1;
    if (chdir("/") < 0) return 1;
    if (cfg->nice_value != 0) nice(cfg->nice_value);
    char *exec_argv[] = { cfg->command, NULL };
    execv(cfg->command, exec_argv);
    return 1;
}

int register_with_monitor(int monitor_fd, const char *container_id, pid_t host_pid, unsigned long soft, unsigned long hard)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft;
    req.hard_limit_bytes = hard;
    snprintf(req.container_id, sizeof(req.container_id), "%s", container_id);
    return ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0 ? -1 : 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    snprintf(req.container_id, sizeof(req.container_id), "%s", container_id);
    return ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0 ? -1 : 0;
}

static container_record_t *find_container(supervisor_ctx_t *ctx, const char *id)
{
    container_record_t *c = ctx->containers;
    while (c) {
        if (strncmp(c->id, id, CONTAINER_ID_LEN) == 0) return c;
        c = c->next;
    }
    return NULL;
}

static void prepend_container(supervisor_ctx_t *ctx, container_record_t *rec)
{
    rec->next       = ctx->containers;
    ctx->containers = rec;
}

static void sigchld_handler(int sig)
{
    (void)sig;
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (!g_ctx) continue;
        pthread_mutex_lock(&g_ctx->metadata_lock);
        container_record_t *c = g_ctx->containers;
        while (c) {
            if (c->host_pid == pid) {
                if (WIFEXITED(status)) {
                    c->exit_code = WEXITSTATUS(status);
                    c->state     = CONTAINER_EXITED;
                } else if (WIFSIGNALED(status)) {
                    c->exit_signal = WTERMSIG(status);
                    c->state = c->stop_requested ? CONTAINER_STOPPED : (WTERMSIG(status) == SIGKILL ? CONTAINER_HARD_LIMIT_KILLED : CONTAINER_KILLED);
                }
                if (g_ctx->monitor_fd >= 0) unregister_from_monitor(g_ctx->monitor_fd, c->id, c->host_pid);
                break;
            }
            c = c->next;
        }
        pthread_mutex_unlock(&g_ctx->metadata_lock);
    }
}

static void sigterm_handler(int sig)
{
    (void)sig;
    if (g_ctx) g_ctx->should_stop = 1;
}

static int launch_container(supervisor_ctx_t *ctx, const control_request_t *req, control_response_t *resp)
{
    pthread_mutex_lock(&ctx->metadata_lock);
    if (find_container(ctx, req->container_id)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp->status = -1;
        snprintf(resp->message, sizeof(resp->message), "ERROR: container exists");
        return -1;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    child_config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) return -1;
    snprintf(cfg->id, sizeof(cfg->id), "%s", req->container_id);
    snprintf(cfg->rootfs, sizeof(cfg->rootfs), "%s", req->rootfs);
    snprintf(cfg->command, sizeof(cfg->command), "%s", req->command);
    cfg->log_write_fd = pipefd[1];

    char *stack = malloc(STACK_SIZE);
    char *stack_top = stack + STACK_SIZE;
    pid_t pid = clone(child_fn, stack_top, CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD, cfg);
    if (pid < 0) { free(stack); free(cfg); close(pipefd[0]); close(pipefd[1]); return -1; }

    close(pipefd[1]);
    container_record_t *rec = calloc(1, sizeof(*rec));
    snprintf(rec->id, sizeof(rec->id), "%s", req->container_id);
    rec->host_pid = pid;
    rec->started_at = time(NULL);
    rec->state = CONTAINER_RUNNING;
    rec->pipe_read_fd = pipefd[0];
    snprintf(rec->log_path, sizeof(rec->log_path), "%s/%s.log", LOG_DIR, req->container_id);

    pthread_mutex_lock(&ctx->metadata_lock);
    prepend_container(ctx, rec);
    pthread_mutex_unlock(&ctx->metadata_lock);

    if (ctx->monitor_fd >= 0) register_with_monitor(ctx->monitor_fd, req->container_id, pid, req->soft_limit_bytes, req->hard_limit_bytes);

    producer_args_t *pa = malloc(sizeof(*pa));
    pa->ctx = ctx; pa->pipe_read_fd = pipefd[0];
    snprintf(pa->container_id, sizeof(pa->container_id), "%s", req->container_id);
    pthread_t tid;
    pthread_create(&tid, NULL, producer_thread, pa);
    pthread_detach(tid);

    free(stack); free(cfg);
    resp->status = 0;
    snprintf(resp->message, sizeof(resp->message), "started %s", req->container_id);
    return 0;
}

static void build_ps_output(supervisor_ctx_t *ctx, char *buf, size_t sz)
{
    size_t off = 0;
    pthread_mutex_lock(&ctx->metadata_lock);
#define APPEND(...) do { int _n = snprintf(buf + off, sz - off, __VA_ARGS__); if (_n > 0) off += (size_t)_n; } while(0)
    APPEND("%-16s %-8s %-20s %-20s\n", "ID", "PID", "STARTED", "STATE");
    container_record_t *c = ctx->containers;
    while (c && off < sz - 1) {
        char tbuf[32];
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&c->started_at));
        APPEND("%-16s %-8d %-20s %-20s\n", c->id, c->host_pid, tbuf, state_to_string(c->state));
        c = c->next;
    }
#undef APPEND
    pthread_mutex_unlock(&ctx->metadata_lock);
}

static void handle_client(supervisor_ctx_t *ctx, int cfd)
{
    control_request_t req;
    control_response_t resp;
    memset(&resp, 0, sizeof(resp));
    if (read(cfd, &req, sizeof(req)) != (ssize_t)sizeof(req)) return;

    switch (req.kind) {
    case CMD_START:
    case CMD_RUN:
        launch_container(ctx, &req, &resp);
        SEND(cfd, &resp, sizeof(resp));
        break;
    case CMD_PS:
        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message), "=== PS ===");
        SEND(cfd, &resp, sizeof(resp));
        char psbuf[8192];
        build_ps_output(ctx, psbuf, sizeof(psbuf));
        SEND(cfd, psbuf, strlen(psbuf));
        break;
    case CMD_LOGS: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = find_container(ctx, req.container_id);
        char log_path[PATH_MAX] = {0};
        if (c) snprintf(log_path, sizeof(log_path), "%s", c->log_path);
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp.status = 0; SEND(cfd, &resp, sizeof(resp));
        int lfd = open(log_path, O_RDONLY);
        if (lfd >= 0) {
            char lbuf[4096]; ssize_t lr;
            while ((lr = read(lfd, lbuf, sizeof(lbuf))) > 0) SEND(cfd, lbuf, (size_t)lr);
            close(lfd);
        }
        break;
    }
    case CMD_STOP: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = find_container(ctx, req.container_id);
        if (c) { c->stop_requested = 1; kill(c->host_pid, SIGTERM); }
        pthread_mutex_unlock(&ctx->metadata_lock);
        break;
    }
    default: break;
    }
    close(cfd);
}

static int run_supervisor(const char *rootfs)
{
    (void)rootfs;
    supervisor_ctx_t ctx; memset(&ctx, 0, sizeof(ctx)); g_ctx = &ctx;
    bounded_buffer_init(&ctx.log_buffer);
    pthread_mutex_init(&ctx.metadata_lock, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler; sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    sa.sa_handler = sigterm_handler; sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);

    ctx.monitor_fd = open(MONITOR_DEVICE, O_RDWR);
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CONTROL_PATH);
    unlink(CONTROL_PATH);
    bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(ctx.server_fd, 16);
    pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);

    while (!ctx.should_stop) {
        int cfd = accept(ctx.server_fd, NULL, NULL);
        if (cfd >= 0) handle_client(&ctx, cfd);
    }
    
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);
    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
    close(ctx.server_fd);
    unlink(CONTROL_PATH);
    return 0;
}

static int send_control_request(const control_request_t *req)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CONTROL_PATH);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return 1; }

    if (write(fd, req, sizeof(*req)) != (ssize_t)sizeof(*req)) { perror("write failed"); close(fd); return 1; }

    control_response_t resp; memset(&resp, 0, sizeof(resp));
    if (read(fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) { perror("read failed"); close(fd); return 1; }
    printf("%s\n", resp.message);

    if (req->kind == CMD_LOGS || req->kind == CMD_PS) {
        char buf[4096]; ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) fwrite(buf, 1, (size_t)n, stdout);
    }
    close(fd);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }
    if (strcmp(argv[1], "supervisor") == 0) return run_supervisor(argv[2]);
    control_request_t req; memset(&req, 0, sizeof(req));
    if (strcmp(argv[1], "start") == 0) {
        req.kind = CMD_START;
        snprintf(req.container_id, sizeof(req.container_id), "%s", argv[2]);
        snprintf(req.rootfs, sizeof(req.rootfs), "%s", argv[3]);
        snprintf(req.command, sizeof(req.command), "%s", argv[4]);
        parse_optional_flags(&req, argc, argv, 5);
        return send_control_request(&req);
    }
    if (strcmp(argv[1], "ps") == 0) { req.kind = CMD_PS; return send_control_request(&req); }
    return 1;
}
