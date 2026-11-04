/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/*
 * The few kernel types the cotty guard reads, declared by hand for CO-RE
 * instead of a generated vmlinux.h. Every struct carries
 * preserve_access_index, so libbpf and cilium/ebpf relocate each field
 * access against the running kernel's BTF: offsets and sizes here do not
 * matter, only the type and field names do. Fields not used by
 * bpf/guard.bpf.c are left out on purpose.
 */
#ifndef __COTTY_VMLINUX_H__
#define __COTTY_VMLINUX_H__

typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef _Bool bool;
#define true 1
#define false 0

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;
typedef __u16 umode_t;
typedef __u32 dev_t;
typedef unsigned int fmode_t;
typedef int pid_t;

/* From include/uapi/linux/bpf.h: only what the program uses. */
enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

enum {
	BPF_F_NO_PREALLOC = 1U << 0,
};

enum {
	BPF_LOCAL_STORAGE_GET_F_CREATE = 1ULL << 0,
	BPF_SK_STORAGE_GET_F_CREATE = 1ULL << 0,
};

/* Kernel types, relocated by name. */

typedef struct {
	unsigned int val;
} kuid_t;

typedef struct {
	unsigned int val;
} kgid_t;

typedef struct {
	u64 val;
} kernel_cap_t;

struct kernfs_node {
	u64 id;
} __attribute__((preserve_access_index));

struct cgroup_subsys_state {
	struct cgroup_subsys_state *parent;
} __attribute__((preserve_access_index));

struct cgroup {
	struct cgroup_subsys_state self;
	int level;
	struct kernfs_node *kn;
	/* ancestors[level] is the cgroup itself (Linux 6.1 and later). */
	struct cgroup *ancestors[];
} __attribute__((preserve_access_index));

struct css_set {
	struct cgroup *dfl_cgrp;
} __attribute__((preserve_access_index));

struct cred {
	kuid_t uid;
	kgid_t gid;
	kuid_t euid;
	kgid_t egid;
	kernel_cap_t cap_permitted;
} __attribute__((preserve_access_index));

struct upid {
	int nr;
} __attribute__((preserve_access_index));

struct pid {
	unsigned int level;
	struct upid numbers[1];
} __attribute__((preserve_access_index));

struct tty_struct {
	/* For a pts slave: the devpts dentry (drivers/tty/pty.c, ptmx_open). */
	void *driver_data;
} __attribute__((preserve_access_index));

/* file->private_data of an open terminal (drivers/tty/tty_io.c). */
struct tty_file_private {
	struct tty_struct *tty;
} __attribute__((preserve_access_index));

struct signal_struct {
	struct tty_struct *tty;
} __attribute__((preserve_access_index));

struct file;

/* The executable a task runs (what /proc/PID/exe shows). */
struct mm_struct {
	struct file *exe_file;
} __attribute__((preserve_access_index));

struct task_struct {
	unsigned int ptrace; /* non-zero while the task is traced */
	struct mm_struct *mm;
	pid_t pid;
	pid_t tgid;
	struct task_struct *group_leader;
	struct signal_struct *signal;
	const struct cred *real_cred;
	const struct cred *cred;
	struct css_set *cgroups;
	char comm[16];
	u64 start_boottime;
} __attribute__((preserve_access_index));

struct super_block {
	dev_t s_dev;
	unsigned long s_magic;
} __attribute__((preserve_access_index));

struct inode {
	umode_t i_mode;
	struct super_block *i_sb;
	unsigned long i_ino;
	dev_t i_rdev;
	u32 i_generation;
} __attribute__((preserve_access_index));

struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	void *d_fsdata;
} __attribute__((preserve_access_index));

struct vfsmount;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	struct inode *f_inode;
	fmode_t f_mode;
	unsigned int f_flags;
	void *private_data;
} __attribute__((preserve_access_index));

struct proc_inode {
	struct pid *pid;
	struct inode vfs_inode;
} __attribute__((preserve_access_index));

struct sock_common {
	unsigned short skc_family;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct socket {
	short type;
	struct sock *sk;
} __attribute__((preserve_access_index));

struct unix_sock {
	struct sock sk;
	struct path path;
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file;
	struct cred *cred;
} __attribute__((preserve_access_index));

struct kernel_siginfo;
struct rlimit;
union bpf_attr;
struct sockaddr;
struct pt_regs;

#endif /* __COTTY_VMLINUX_H__ */
