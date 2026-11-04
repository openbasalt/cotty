// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
/*
 * cotty-guard: BPF LSM programs that enforce the agent rules in the kernel
 * (docs/PLAN.md, section 4, layer 3; docs/guard.md).
 *
 * Who is an agent:
 *   - every task in a cgroup registered in agent_cgroups, or below one
 *     (the cgroup of `cotty agent`, registered by the launcher through the
 *     daemon before the agent starts), at any depth;
 *   - every task whose task storage (or whose thread group leader's task
 *     storage) carries a tag. The tag is copied explicitly to every new
 *     task in task_alloc (task storage is not inherited by itself; a task
 *     that cannot be tagged is not created) and set in bprm_creds_for_exec
 *     for tasks found by cgroup, so it survives a later cgroup move. The
 *     daemon also sets it for a process that asks to tag itself.
 * The tag value is the agent id: the registered cgroup's id, or an id the
 * daemon allocated for a self tag. Tags are never removed, and the maps
 * stay pinned when the daemon stops, so a restart keeps them.
 *
 * What an agent may not do (each denial is sent to the daemon through the
 * events ring buffer, rate limited per process, and ends in the audit log):
 *   ptrace_access_check  any ptrace-style access (ptrace, process_vm_*,
 *                        /proc/PID/{mem,environ,fd/N,root,...}, pidfd_getfd)
 *                        to a task that is not of the same agent;
 *   file_open            /proc/PID/{mem,environ,fd,fdinfo,maps,...} of a
 *                        task that is not of the same agent; input devices,
 *                        /dev/uinput, /dev/uhid, /dev/vcs*; any cgroup v2
 *                        file opened for writing (cgroup.procs, cgroup.kill,
 *                        cgroup.freeze, limits); /dev/tty when it is a
 *                        protected session pts;
 *   unix_stream_connect,
 *   unix_may_send        a Unix socket that is not the agent's own (created
 *                        by the same agent), not on the agent's allowlist
 *                        (the cotty agent socket, profile sockets) and not
 *                        on the global allowlist (resolver, journal, userdb,
 *                        nscd), by inode of the socket or of the directory
 *                        holding it; abstract sockets are only allowed when
 *                        the agent created them;
 *   inode_* (also for every non-root process that is not a registered
 *   broker, in cotty runtime directories: binding, linking, symlinking,
 *   renaming or removing, while the daemon runs)
 *                        creating, linking, renaming or removing anything
 *                        in a directory the agent's registration marks as
 *                        guarded (the cotty runtime directory and every
 *                        allowed socket directory), or renaming or removing
 *                        such a directory: no socket can be planted in, or
 *                        moved into, a place the agent or the person trusts;
 *   bprm_creds_from_file an exec that would gain privileges (setuid,
 *                        setgid, file capabilities);
 *   bpf                  the bpf() syscall;
 *   task_kill,
 *   task_setrlimit, task_setnice, task_setioprio, task_setscheduler
 *                        a signal, a resource limit or a scheduling change
 *                        for a task that is not of the same agent;
 *   file_fcntl           F_SETOWN, F_SETOWN_EX (SIGIO signals to any task),
 *                        F_SETSIG and O_ASYNC through F_SETFL (a terminal
 *                        sends SIGIO to its foreground process group by
 *                        itself once O_ASYNC is set);
 *   file_ioctl(_compat)  TIOCSTI and TIOCLINUX (input injection), FIOSETOWN,
 *                        SIOCSPGRP and FIOASYNC (SIGIO owner and O_ASYNC).
 *
 * For every task, agent or not: a protected pts (a cotty session's) opens
 * or arrives through SCM_RIGHTS/pidfd_getfd (file_receive) only for the
 * broker that protected it and for the processes whose controlling
 * terminal it is, never for an agent; a task that is not an agent and is
 * not traced may also open it when the executable it runs is on the
 * exception list (pts_exceptions: a pinentry-curses started by gpg-agent
 * with GPG_TTY), and each such open is recorded for the broker
 * (pts_exc_uses) and reported to the daemon; and the session's processes cannot
 * be ptrace-attached (ptrace, pidfd_getfd, process_vm_*, /proc/PID/mem) by
 * a non-root process outside the session. A protection ends with the
 * broker: an entry whose owner is gone is ignored (the daemon removes it;
 * the programs never delete, so they cannot race a daemon update).
 *
 * For every non-root task, registered brokers included: a session socket a
 * broker claimed (broker_socks) cannot be unlinked, renamed or replaced
 * while that broker runs, so a second broker cannot take a session over.
 */
#include "cotty_vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define ENOMEM 12

#define S_IFMT 00170000
#define S_IFCHR 0020000
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)

#define PROC_SUPER_MAGIC 0x9fa0
#define DEVPTS_SUPER_MAGIC 0x1cd1
#define CGROUP2_SUPER_MAGIC 0x63677270

#define FMODE_WRITE 0x2
#define O_PATH 010000000
#define AF_UNIX 1
#define PTRACE_MODE_ATTACH 0x02
#define PTRACE_MODE_NOAUDIT 0x04
#define TIOCSTI 0x5412
#define TIOCLINUX 0x541C
#define FIOSETOWN 0x8901
#define SIOCSPGRP 0x8902
#define F_SETFL 4
#define F_SETOWN 8
#define F_SETSIG 10
#define F_SETOWN_EX 15
#define O_ASYNC 020000
#define FIOASYNC 0x5452
#define CLONE_INTO_CGROUP 0x200000000ULL

#define TTYAUX_MAJOR 5
#define VCS_MAJOR 7
#define INPUT_MAJOR 13
#define MISC_MAJOR 10
#define UINPUT_MINOR 223
#define UHID_MINOR 239
#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

/* Levels of the cgroup tree the daemon accepts registrations at (the
 * level mask in guard_state is 64 bits). */
#define MAX_CGROUP_LEVEL 63

/* Clock ticks per second of /proc/PID/stat's start time (USER_HZ, 100 on
 * every architecture cotty supports); the daemon records a broker's start
 * in these units. */
#define NSEC_PER_TICK 10000000ULL

/* Denial events per process and second sent to the daemon; the rest are
 * counted in guard_state[STATE_DROPPED]. */
#define EVENTS_PER_SEC 32

/* allowed_socks values. */
#define SOCK_CONNECT 1	/* connect/send to the socket, or to sockets directly in the directory */
#define DIR_GUARDED 2	/* the agent may not create, link, rename or remove entries in the directory */
#define DIR_BROKERS 4	/* a cotty runtime directory: only registered brokers (and root) may bind, link,
			 * symlink, rename or remove entries there, while the daemon runs */

/* guard_state slots. */
#define STATE_AGENTS 0	/* number of registered agent cgroups (skip the walk when 0) */
#define STATE_LEVELS 1	/* bit L set: some registered cgroup is at level L */
#define STATE_DROPPED 2 /* denial events not sent (rate limit or full ring buffer) */
#define STATE_HEARTBEAT 3 /* CLOCK_MONOTONIC ns of the daemon's last heartbeat (0: none yet) */

/* The broker directory rule and the pts exception list hold while the
 * daemon's heartbeat (every 30 s) is younger than this: with no daemon,
 * brokers cannot register, so the rule would stop new sessions from
 * starting, and no broker can learn about an exception use, so the lock
 * would not light for it. */
#define HEARTBEAT_NS (90ULL * 1000000000ULL)

/* Hooks and reasons, mirrored in internal/guard/events.go. */
enum hook {
	HOOK_PTRACE = 1,
	HOOK_FILE_OPEN = 2,
	HOOK_UNIX_CONNECT = 3,
	HOOK_UNIX_SEND = 4,
	HOOK_EXEC = 5,
	HOOK_BPF = 6,
	HOOK_KILL = 7,
	HOOK_IOCTL = 8,
	HOOK_FILE_RECEIVE = 9,
	HOOK_INODE = 10,
	HOOK_TASK_SET = 11,
	HOOK_FCNTL = 12,
	HOOK_TASK_ALLOC = 13,
};

enum reason {
	R_OTHER_TASK = 1,
	R_PROC_FILE = 2,
	R_SESSION_PTS = 3,
	R_INPUT_DEVICE = 4,
	R_CGROUP_MIGRATE = 5,
	R_UNIX_SOCKET = 6,
	R_ABSTRACT_SOCKET = 7,
	R_PRIV_EXEC = 8,
	R_BPF = 9,
	R_TIOCSTI = 10,
	R_CGROUP_WRITE = 11,
	R_GUARDED_DIR = 12,
	R_SESSION_PROC = 13,
	R_SIGIO = 14,
	R_UNTAGGABLE = 15,
	R_BROKER_DIR = 16,
	R_BROKER_SOCK = 17,
	R_PTS_EXCEPTION = 18, /* not a denial: a listed executable opened a protected pts */
};

/* event.extra: the event reports an access the rules allowed. */
#define EV_ALLOWED 1

struct event {
	u64 agent;
	u64 dev;
	u64 ino;
	u32 hook;
	u32 reason;
	u32 pid;
	u32 tgid;
	u32 target;
	u32 extra;
	char comm[16];
	char name[32];
};

/* Keeps struct event in the object's BTF for bpf2go (-type event); the
 * ring buffer API itself carries no type. */
const struct event *unused_event __attribute__((unused));

struct tag {
	u64 agent;
};

/* A file identified by its device (kernel encoding) and inode number. */
struct file_key {
	u64 agent; /* 0 for global entries */
	u64 dev;
	u64 ino;
};

/* cgroup id -> agent id. Written only by the daemon. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, u64);
	__type(value, u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} agent_cgroups SEC(".maps");

/* Per task agent tag. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tag);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} agent_tasks SEC(".maps");

/* Unix sockets created by an agent: owner agent id. */
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tag);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} agent_socks SEC(".maps");

/* Socket allowlist and guarded directories: {agent, dev, ino} of a socket
 * or of a directory -> SOCK_CONNECT | DIR_GUARDED; agent 0 is the global
 * list. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct file_key);
	__type(value, u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} allowed_socks SEC(".maps");

/* A protected terminal's owner: the broker that registered it. */
struct pts_owner {
	u32 tgid;  /* global tgid of the broker */
	u32 uid;   /* its uid (per-user quota in the daemon) */
	u64 start; /* its start time in clock ticks since boot (/proc/PID/stat field 22) */
};

/* Protected terminals (a cotty session's pts): {0, dev, ino} -> owner. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct file_key);
	__type(value, struct pts_owner);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} protected_files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, u32);
	__type(value, u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} guard_state SEC(".maps");

/* daemon_alive tells whether the daemon's last heartbeat is younger than
 * HEARTBEAT_NS (0, after a clean stop or before the first heartbeat, is
 * never alive). */
static __always_inline bool daemon_alive(void)
{
	u32 slot = STATE_HEARTBEAT;
	u64 *hb = bpf_map_lookup_elem(&guard_state, &slot);
	return hb && *hb && bpf_ktime_get_ns() - *hb < HEARTBEAT_NS;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

/* The pts exception list: executables that may open a protected pts
 * without having it as their controlling terminal, by the file's
 * superblock device (kernel encoding, super_block.s_dev), inode number and
 * inode generation. The generation tells apart files with the same inode
 * number in different btrfs subvolumes, which share one superblock (a
 * user can create subvolumes, and files in them, until a number repeats).
 * Written only by the daemon, from a root-owned configuration file. */
struct exe_key {
	u64 dev;
	u64 ino;
};

#define EXC_ANY_GEN 1 /* exe_val.flags: the filesystem keeps no generation the daemon can read */

struct exe_val {
	u32 gen;
	u32 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct exe_key);
	__type(value, struct exe_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pts_exceptions SEC(".maps");

/* The last exception use of each protected pts: {0, dev, ino} of the pts
 * -> the process that opened it and the executable it ran. The daemon
 * answers the pts's broker from it (the lock names the program). */
struct exc_use {
	u32 tgid;
	u32 pad;
	u64 start; /* clock ticks since boot, as /proc/PID/stat shows it */
	u64 exe_dev;
	u64 exe_ino;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct file_key);
	__type(value, struct exc_use);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pts_exc_uses SEC(".maps");

/* Registered cotty brokers: tgid -> start time in clock ticks since boot
 * (the leader's, as /proc/PID/stat shows it). Written only by the daemon,
 * after it checked the caller runs the installed cotty binary as a
 * broker. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, u32);
	__type(value, u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} brokers SEC(".maps");

/* Registered session names: {uid, name} -> the broker that registered the
 * name first and still runs, with its runtime directories and the
 * sockets it claimed. Only the daemon reads and writes it (it lives in a
 * pinned map so that it survives a daemon restart, like the rest). */
struct broker_name {
	u32 uid;
	char name[36];
};

struct broker_reg {
	u32 tgid;
	u32 pad;
	u64 start;    /* clock ticks since boot, as /proc/PID/stat shows it */
	u64 dir_dev;  /* the runtime directory */
	u64 dir_ino;
	u64 adir_dev; /* its agent directory */
	u64 adir_ino;
	u64 sock_dev; /* the claimed person socket */
	u64 sock_ino;
	u64 asock_dev; /* the claimed agent socket */
	u64 asock_ino;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct broker_name);
	__type(value, struct broker_reg);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} broker_names SEC(".maps");

/* Session sockets claimed by their broker: {0, dev, ino} -> the broker.
 * Written only by the daemon, for the registered broker of the session. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct file_key);
	__type(value, struct pts_owner);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} broker_socks SEC(".maps");

/* Denial events sent in the current one second window, per agent (all of
 * an agent's processes share one budget) or, for a task that is not an
 * agent, per process. */
struct rate_key {
	u64 agent;
	u32 tgid; /* 0 for an agent */
	u32 pad;
};

struct rate {
	u64 window;
	u64 count;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct rate_key);
	__type(value, struct rate);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} event_rate SEC(".maps");

extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

static __always_inline void count_dropped(void)
{
	u32 slot = STATE_DROPPED;
	u64 *n = bpf_map_lookup_elem(&guard_state, &slot);
	if (n)
		__sync_fetch_and_add(n, 1);
}

/* cgroup_agent finds a registered cgroup among the task's cgroup v2
 * ancestors (itself included). Only the levels where some cgroup is
 * registered are looked at, through cgroup->ancestors[], so any depth
 * below a registered cgroup is covered. */
static __always_inline u64 cgroup_agent(struct task_struct *t)
{
	u32 slot = STATE_AGENTS;
	u64 *n = bpf_map_lookup_elem(&guard_state, &slot);
	if (!n || *n == 0)
		return 0;
	slot = STATE_LEVELS;
	u64 *mp = bpf_map_lookup_elem(&guard_state, &slot);
	if (!mp)
		return 0;
	u64 mask = *mp;
	struct cgroup *cg = BPF_CORE_READ(t, cgroups, dfl_cgrp);
	if (!cg)
		return 0;
	int level = BPF_CORE_READ(cg, level);
	unsigned long base = (unsigned long)cg + bpf_core_field_offset(struct cgroup, ancestors);
	for (int i = 0; i <= MAX_CGROUP_LEVEL; i++) {
		if (i > level)
			break;
		if (!((mask >> i) & 1))
			continue;
		struct cgroup *anc = 0;
		bpf_probe_read_kernel(&anc, sizeof(anc), (void *)(base + i * sizeof(void *)));
		if (!anc)
			continue;
		u64 id = BPF_CORE_READ(anc, kn, id);
		u64 *agent = bpf_map_lookup_elem(&agent_cgroups, &id);
		if (agent)
			return *agent;
	}
	return 0;
}

/* stored_agent reads the tag of a task or of its thread group leader. */
static __always_inline u64 stored_agent(struct task_struct *t)
{
	struct tag *tg = bpf_task_storage_get(&agent_tasks, t, 0, 0);
	if (tg && tg->agent)
		return tg->agent;
	struct task_struct *leader = t->group_leader;
	if (leader && leader != t) {
		tg = bpf_task_storage_get(&agent_tasks, leader, 0, 0);
		if (tg && tg->agent)
			return tg->agent;
	}
	return 0;
}

/* agent_of returns the agent id of a task, 0 when it is not an agent. */
static __always_inline u64 agent_of(struct task_struct *t)
{
	u64 a = stored_agent(t);
	if (a)
		return a;
	return cgroup_agent(t);
}

/* set_tag tags a task; false when the kernel could not allocate storage. */
static __always_inline bool set_tag(struct task_struct *t, u64 agent)
{
	struct tag *tg = bpf_task_storage_get(&agent_tasks, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tg)
		return false;
	if (!tg->agent)
		tg->agent = agent;
	return true;
}

/* rate_ok admits at most EVENTS_PER_SEC denial events per agent (or per
 * process for a task that is not an agent) and second, so a looping
 * program, or many processes of one agent, cannot flood the ring buffer. */
static __always_inline bool rate_ok(u64 agent, u32 tgid)
{
	u64 now = bpf_ktime_get_ns();
	struct rate_key rk = { .agent = agent, .tgid = agent ? 0 : tgid, .pad = 0 };
	struct rate *r = bpf_map_lookup_elem(&event_rate, &rk);
	if (!r) {
		struct rate nr = { .window = now, .count = 1 };
		bpf_map_update_elem(&event_rate, &rk, &nr, BPF_ANY);
		return true;
	}
	if (now - r->window > 1000000000ULL) {
		r->window = now;
		r->count = 0;
	}
	if (r->count >= EVENTS_PER_SEC)
		return false;
	r->count++;
	return true;
}

/* report sends one event to the daemon (rate limited); extra is 0 for a
 * denial, EV_ALLOWED for an allowed access the daemon must log. */
static __always_inline void report(u64 agent, u32 hook, u32 reason, u32 target, u64 dev, u64 ino,
				   const unsigned char *name, u32 extra)
{
	u64 pt = bpf_get_current_pid_tgid();
	if (!rate_ok(agent, pt >> 32)) {
		count_dropped();
		return;
	}
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_dropped();
		return;
	}
	e->agent = agent;
	e->dev = dev;
	e->ino = ino;
	e->hook = hook;
	e->reason = reason;
	e->pid = (u32)pt;
	e->tgid = pt >> 32;
	e->target = target;
	e->extra = extra;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->name[0] = 0;
	if (name)
		bpf_probe_read_kernel_str(e->name, sizeof(e->name), name);
	bpf_ringbuf_submit(e, 0);
}

static __always_inline int deny(u64 agent, u32 hook, u32 reason, u32 target, u64 dev, u64 ino,
				const unsigned char *name)
{
	report(agent, hook, reason, target, dev, ino, name, 0);
	return -EPERM;
}

static __always_inline u64 current_agent(void)
{
	return agent_of(bpf_get_current_task_btf());
}

/* ---- protected session terminals ---- */

/* owner_alive tells whether the broker that protected a pts still runs
 * (same tgid and same start time, so a reused pid does not count). */
static __always_inline bool owner_alive(struct pts_owner *o)
{
	struct task_struct *t = bpf_task_from_pid(o->tgid);
	if (!t)
		return false;
	u64 start = BPF_CORE_READ(t, start_boottime) / NSEC_PER_TICK;
	bpf_task_release(t);
	return start == o->start;
}

/* protection returns the live owner of a protected pts, NULL when the pts
 * is not protected. An entry whose broker is gone is ignored; the daemon
 * removes it (deleting here could remove a fresh entry the daemon wrote
 * for a reused pts between the lookup and the delete). */
static __always_inline struct pts_owner *protection(struct file_key *k)
{
	struct pts_owner *o = bpf_map_lookup_elem(&protected_files, k);
	if (!o)
		return 0;
	if (owner_alive(o))
		return o;
	return 0;
}


/* tty_key fills k with the devpts inode of a pts slave tty; false for any
 * other terminal. */
static __always_inline bool tty_key(struct tty_struct *tty, struct file_key *k)
{
	if (!tty)
		return false;
	/* A pts slave keeps its devpts dentry in driver_data, and the dentry
	 * points back at the tty in d_fsdata; for any other terminal
	 * driver_data is something else and the back pointer does not match
	 * (both reads are probe reads, safe on any pointer). */
	struct dentry *d = BPF_CORE_READ(tty, driver_data);
	if (!d || BPF_CORE_READ(d, d_fsdata) != (void *)tty)
		return false;
	struct inode *in = BPF_CORE_READ(d, d_inode);
	if (!in || BPF_CORE_READ(in, i_sb, s_magic) != DEVPTS_SUPER_MAGIC)
		return false;
	k->agent = 0;
	k->dev = BPF_CORE_READ(in, i_sb, s_dev);
	k->ino = BPF_CORE_READ(in, i_ino);
	return true;
}

/* exception_open tells whether the current task (not an agent: the caller
 * checked) may open the protected pts k because the executable it runs is
 * on the exception list, and records the use for the pts's broker. The
 * executable is the file the task runs (mm->exe_file, the inode the
 * kernel mapped), not its name or arguments. A traced task runs what its
 * tracer makes it run: it never passes. */
static __always_inline bool exception_open(struct task_struct *cur, struct pts_owner *owner, struct file_key *k,
					   const unsigned char *name)
{
	/* The exception lives with the daemon: only a running daemon can tell
	 * the session's broker about the use (pts-exception), and without that
	 * the lock would not light. With no heartbeat for HEARTBEAT_NS (a
	 * crash) the exception lapses and the pts is refused as before. A
	 * clean stop empties pts_exceptions at once. */
	if (!daemon_alive())
		return false;
	if (BPF_CORE_READ(cur, ptrace))
		return false;
	struct file *exe = BPF_CORE_READ(cur, mm, exe_file);
	if (!exe)
		return false;
	struct inode *in = BPF_CORE_READ(exe, f_inode);
	if (!in)
		return false;
	struct exe_key ek = { .dev = BPF_CORE_READ(in, i_sb, s_dev), .ino = BPF_CORE_READ(in, i_ino) };
	struct exe_val *v = bpf_map_lookup_elem(&pts_exceptions, &ek);
	if (!v)
		return false;
	if (!(v->flags & EXC_ANY_GEN) && BPF_CORE_READ(in, i_generation) != v->gen)
		return false;
	struct exc_use u = {
		.tgid = bpf_get_current_pid_tgid() >> 32,
		.pad = 0,
		.start = BPF_CORE_READ(cur, group_leader, start_boottime) / NSEC_PER_TICK,
		.exe_dev = ek.dev,
		.exe_ino = ek.ino,
	};
	bpf_map_update_elem(&pts_exc_uses, k, &u, BPF_ANY);
	report(0, HOOK_FILE_OPEN, R_PTS_EXCEPTION, owner->tgid, k->dev, k->ino, name, EV_ALLOWED);
	return true;
}

/* session_tty decides access to the protected terminal tty for the
 * current task: its broker and the processes whose controlling terminal
 * it is (not agents) pass, and so does an open (not a received
 * descriptor) by a task that is not an agent and runs an executable on
 * the exception list. The agent check comes first: an agent, or any task
 * it started, never gets an exception. */
static __always_inline int session_tty(void *tty, struct pts_owner *owner, struct file_key *k, u32 hook,
				       const unsigned char *name)
{
	struct task_struct *cur = bpf_get_current_task_btf();
	u64 a = agent_of(cur);
	if (!a) {
		if ((u32)(bpf_get_current_pid_tgid() >> 32) == owner->tgid)
			return 0;
		struct tty_struct *ctty = BPF_CORE_READ(cur, signal, tty);
		if (tty && (void *)ctty == tty)
			return 0;
		if (hook == HOOK_FILE_OPEN && exception_open(cur, owner, k, name))
			return 0;
	}
	return deny(a, hook, R_SESSION_PTS, owner->tgid, k->dev, k->ino, name);
}

/*
 * pts_rule decides access to a file that may be a protected terminal (a
 * cotty session's pts), for every task, agent or not: only the broker that
 * protected it and the processes whose controlling terminal it is (the
 * session's own commands) may open or receive it. Opening through
 * /proc/PID/fd/N of the session's shell reaches the same file, so the
 * same rule applies to it. A file opened through /dev/tty (5:0) is the
 * opener's controlling terminal: with tty_files set, it is resolved
 * through the open file (for descriptors passed around, file_receive).
 * Returns 1 when the file is not a protected pts.
 */
static __always_inline int pts_rule(struct file *file, struct inode *inode, u32 hook, bool tty_files)
{
	umode_t mode = BPF_CORE_READ(inode, i_mode);
	if (!S_ISCHR(mode))
		return 1;
	const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	struct file_key k = { .agent = 0 };
	void *tty;
	if (BPF_CORE_READ(inode, i_sb, s_magic) == DEVPTS_SUPER_MAGIC) {
		k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
		k.ino = BPF_CORE_READ(inode, i_ino);
		/* devpts keeps the slave's tty_struct in the dentry. */
		tty = BPF_CORE_READ(file, f_path.dentry, d_fsdata);
	} else if (tty_files && BPF_CORE_READ(inode, i_rdev) == (TTYAUX_MAJOR << MINORBITS)) {
		struct tty_file_private *priv = BPF_CORE_READ(file, private_data);
		if (!priv)
			return 1;
		tty = BPF_CORE_READ(priv, tty);
		if (!tty_key(tty, &k))
			return 1;
	} else {
		return 1;
	}
	struct pts_owner *owner = protection(&k);
	if (!owner)
		return 1;
	return session_tty(tty, owner, &k, hook, name);
}

/* ---- tags ---- */

SEC("lsm/task_alloc")
int BPF_PROG(cotty_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
	u64 a = current_agent();
	if (!a)
		return 0;
	/* clone3(CLONE_INTO_CGROUP) would start the child in a cgroup of the
	 * person's choosing (any the user may write), outside the agent's
	 * scope, without writing cgroup.procs: refused to agents. */
	if ((u64)clone_flags & CLONE_INTO_CGROUP)
		return deny(a, HOOK_TASK_ALLOC, R_CGROUP_MIGRATE, 0, 0, 0, 0);
	if (!set_tag(task, a)) {
		/* Fail closed: an agent's child that cannot carry the tag would
		 * be outside every rule. */
		deny(a, HOOK_TASK_ALLOC, R_UNTAGGABLE, 0, 0, 0, 0);
		return -ENOMEM;
	}
	return 0;
}

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(cotty_bprm_creds_for_exec, struct linux_binprm *bprm)
{
	struct task_struct *cur = bpf_get_current_task_btf();
	if (stored_agent(cur))
		return 0;
	u64 a = cgroup_agent(cur);
	if (a && !set_tag(cur, a))
		return -ENOMEM;
	return 0;
}

/* ---- rules ---- */

SEC("lsm/ptrace_access_check")
int BPF_PROG(cotty_ptrace_access_check, struct task_struct *child, unsigned int mode)
{
	struct task_struct *cur = bpf_get_current_task_btf();
	u64 a = agent_of(cur);
	if (a) {
		if (agent_of(child) == a)
			return 0;
		/* NOAUDIT checks (ps reading /proc/PID/stat) are denied silently. */
		if (mode & PTRACE_MODE_NOAUDIT)
			return -EPERM;
		return deny(a, HOOK_PTRACE, R_OTHER_TASK, BPF_CORE_READ(child, tgid), 0, 0, 0);
	}
	/* Not an agent: attaching to a process of a protected session (ptrace,
	 * pidfd_getfd, process_vm_*, /proc/PID/mem) is for the session's own
	 * processes, its broker and root only. */
	if (!(mode & PTRACE_MODE_ATTACH))
		return 0;
	struct tty_struct *ctty = BPF_CORE_READ(child, signal, tty);
	struct file_key k;
	if (!tty_key(ctty, &k))
		return 0;
	struct pts_owner *owner = protection(&k);
	if (!owner)
		return 0;
	if ((u32)(bpf_get_current_pid_tgid() >> 32) == owner->tgid)
		return 0;
	if (BPF_CORE_READ(cur, signal, tty) == ctty)
		return 0;
	if (BPF_CORE_READ(cur, cred, euid.val) == 0)
		return 0;
	if (mode & PTRACE_MODE_NOAUDIT)
		return -EPERM;
	return deny(0, HOOK_PTRACE, R_SESSION_PROC, BPF_CORE_READ(child, tgid), k.dev, k.ino, 0);
}

/* Names under /proc/PID (and /proc/PID/task/TID) that expose a task's
 * memory, environment or open files. */
static __always_inline bool sensitive_proc_name(const char *n)
{
	switch (n[0]) {
	case 'm':
		return (n[1] == 'e' && n[2] == 'm' && n[3] == 0) ||
		       (n[1] == 'a' && n[2] == 'p' && n[3] == 's' && n[4] == 0);
	case 'e':
		return n[1] == 'n' && n[2] == 'v' && n[3] == 'i' && n[4] == 'r' && n[5] == 'o' &&
		       n[6] == 'n' && n[7] == 0;
	case 'f':
		return n[1] == 'd' && (n[2] == 0 || (n[2] == 'i' && n[3] == 'n' && n[4] == 'f' &&
						     n[5] == 'o' && n[6] == 0));
	case 's':
		/* smaps, smaps_rollup */
		return n[1] == 'm' && n[2] == 'a' && n[3] == 'p' && n[4] == 's' &&
		       (n[5] == 0 || n[5] == '_');
	case 'p':
		/* pagemap */
		return n[1] == 'a' && n[2] == 'g' && n[3] == 'e' && n[4] == 'm' && n[5] == 'a' &&
		       n[6] == 'p' && n[7] == 0;
	case 'a':
		/* auxv */
		return n[1] == 'u' && n[2] == 'x' && n[3] == 'v' && n[4] == 0;
	}
	return false;
}

static __always_inline bool cgroup_move_file(const char *n)
{
	/* cgroup.procs, cgroup.threads */
	if (!(n[0] == 'c' && n[1] == 'g' && n[2] == 'r' && n[3] == 'o' && n[4] == 'u' && n[5] == 'p' &&
	      n[6] == '.'))
		return false;
	return (n[7] == 'p' && n[8] == 'r' && n[9] == 'o' && n[10] == 'c' && n[11] == 's' && n[12] == 0) ||
	       (n[7] == 't' && n[8] == 'h' && n[9] == 'r' && n[10] == 'e' && n[11] == 'a' && n[12] == 'd' &&
		n[13] == 's' && n[14] == 0);
}

SEC("lsm/file_open")
int BPF_PROG(cotty_file_open, struct file *file)
{
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	/* Protected terminals: checked for every task. */
	int r = pts_rule(file, inode, HOOK_FILE_OPEN, false);
	if (r != 1)
		return r;

	u64 a = current_agent();
	if (!a)
		return 0;

	umode_t mode = BPF_CORE_READ(inode, i_mode);
	unsigned long magic = BPF_CORE_READ(inode, i_sb, s_magic);
	u64 sdev = BPF_CORE_READ(inode, i_sb, s_dev);
	u64 ino = BPF_CORE_READ(inode, i_ino);
	const unsigned char *dname = BPF_CORE_READ(file, f_path.dentry, d_name.name);

	if (S_ISCHR(mode)) {
		u32 rdev = BPF_CORE_READ(inode, i_rdev);
		u32 major = rdev >> MINORBITS, minor = rdev & MINORMASK;
		if (major == INPUT_MAJOR || major == VCS_MAJOR ||
		    (major == MISC_MAJOR && (minor == UINPUT_MINOR || minor == UHID_MINOR)))
			return deny(a, HOOK_FILE_OPEN, R_INPUT_DEVICE, 0, sdev, ino, dname);
		if (major == TTYAUX_MAJOR && minor == 0) {
			/* /dev/tty is the caller's controlling terminal: refused
			 * when that is a protected session pts. */
			struct file_key k;
			struct tty_struct *ctty = BPF_CORE_READ(bpf_get_current_task_btf(), signal, tty);
			if (tty_key(ctty, &k)) {
				struct pts_owner *owner = protection(&k);
				if (owner)
					return deny(a, HOOK_FILE_OPEN, R_SESSION_PTS, owner->tgid, k.dev, k.ino, dname);
			}
		}
		return 0;
	}

	char name[16] = {};
	if (magic == PROC_SUPER_MAGIC) {
		bpf_probe_read_kernel_str(name, sizeof(name), dname);
		if (!sensitive_proc_name(name))
			return 0;
		/* The task behind a /proc/PID entry: proc_inode->pid. */
		unsigned long off = bpf_core_field_offset(struct proc_inode, vfs_inode);
		struct proc_inode *pi = (struct proc_inode *)((unsigned long)inode - off);
		struct pid *pid = BPF_CORE_READ(pi, pid);
		if (!pid)
			return 0; /* not a per-task entry (for example /proc/meminfo is not matched anyway) */
		int nr = BPF_CORE_READ(pid, numbers[0].nr);
		if (nr <= 0)
			return 0;
		struct task_struct *t = bpf_task_from_pid(nr);
		if (!t)
			return 0;
		u64 ta = agent_of(t);
		bpf_task_release(t);
		if (ta == a)
			return 0;
		return deny(a, HOOK_FILE_OPEN, R_PROC_FILE, nr, sdev, ino, dname);
	}

	if (magic == CGROUP2_SUPER_MAGIC && (BPF_CORE_READ(file, f_mode) & FMODE_WRITE)) {
		/* Any write: cgroup.procs/threads move a task out of the agent's
		 * cgroup; cgroup.kill, cgroup.freeze, memory.max, pids.max and the
		 * like would kill, freeze or starve the person's processes (the
		 * broker) without a signal. */
		bpf_probe_read_kernel_str(name, sizeof(name), dname);
		return deny(a, HOOK_FILE_OPEN, cgroup_move_file(name) ? R_CGROUP_MIGRATE : R_CGROUP_WRITE, 0, sdev, ino,
			    dname);
	}
	return 0;
}

/* A descriptor arriving through SCM_RIGHTS or pidfd_getfd: the same rule
 * as opening it, for protected terminals. O_PATH descriptors give no
 * access to the terminal and pass (the broker sends one to the daemon). */
SEC("lsm/file_receive")
int BPF_PROG(cotty_file_receive, struct file *file)
{
	if (BPF_CORE_READ(file, f_flags) & O_PATH)
		return 0;
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;
	int r = pts_rule(file, inode, HOOK_FILE_RECEIVE, true);
	return r == 1 ? 0 : r;
}

/* ---- Unix sockets ---- */

SEC("lsm/socket_post_create")
int BPF_PROG(cotty_socket_post_create, struct socket *sock, int family, int type, int protocol, int kern)
{
	if (family != AF_UNIX || kern)
		return 0;
	u64 a = current_agent();
	if (!a)
		return 0;
	struct sock *sk = sock->sk;
	if (!sk)
		return 0;
	struct tag *tg = bpf_sk_storage_get(&agent_socks, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (tg)
		tg->agent = a;
	return 0;
}

static __always_inline bool sock_allowed(struct file_key *k)
{
	u8 *v = bpf_map_lookup_elem(&allowed_socks, k);
	return v && (*v & SOCK_CONNECT);
}

/* unix_check decides whether agent a may reach the Unix socket other. */
static __always_inline int unix_check(u64 a, u32 hook, struct sock *other)
{
	struct tag *tg = bpf_sk_storage_get(&agent_socks, other, 0, 0);
	if (tg && tg->agent == a)
		return 0;
	struct unix_sock *u = (struct unix_sock *)other;
	struct dentry *d = BPF_CORE_READ(u, path.dentry);
	if (!d)
		return deny(a, hook, R_ABSTRACT_SOCKET, 0, 0, 0, 0);
	struct inode *inode = BPF_CORE_READ(d, d_inode);
	struct file_key k = {
		.agent = 0,
		.dev = BPF_CORE_READ(inode, i_sb, s_dev),
		.ino = BPF_CORE_READ(inode, i_ino),
	};
	if (sock_allowed(&k))
		return 0;
	k.agent = a;
	if (sock_allowed(&k))
		return 0;
	/* An allowed directory allows the sockets directly in it (a socket
	 * directory whose sockets come and go, such as the cotty agent
	 * endpoint directory or /run/systemd/userdb). The agent cannot move a
	 * socket into such a directory: it is guarded (inode hooks below). */
	u64 sino = k.ino;
	k.ino = BPF_CORE_READ(d, d_parent, d_inode, i_ino);
	if (sock_allowed(&k))
		return 0;
	k.agent = 0;
	if (sock_allowed(&k))
		return 0;
	return deny(a, hook, R_UNIX_SOCKET, 0, k.dev, sino, BPF_CORE_READ(d, d_name.name));
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(cotty_unix_stream_connect, struct sock *sock, struct sock *other, struct sock *newsk)
{
	u64 a = current_agent();
	if (!a)
		return 0;
	return unix_check(a, HOOK_UNIX_CONNECT, other);
}

SEC("lsm/unix_may_send")
int BPF_PROG(cotty_unix_may_send, struct socket *sock, struct socket *other)
{
	u64 a = current_agent();
	if (!a)
		return 0;
	struct sock *sk = other->sk;
	if (!sk)
		return 0;
	return unix_check(a, HOOK_UNIX_SEND, sk);
}

/* ---- guarded directories ---- */

static __always_inline bool guarded(u64 a, struct inode *in)
{
	if (!in)
		return false;
	struct file_key k = { .agent = a, .dev = BPF_CORE_READ(in, i_sb, s_dev), .ino = BPF_CORE_READ(in, i_ino) };
	u8 *v = bpf_map_lookup_elem(&allowed_socks, &k);
	if (v && (*v & DIR_GUARDED))
		return true;
	k.agent = 0;
	v = bpf_map_lookup_elem(&allowed_socks, &k);
	return v && (*v & DIR_GUARDED);
}

/* broker_dir tells whether a directory is a cotty runtime directory
 * (registered by a broker). */
static __always_inline bool broker_dir(struct inode *in)
{
	if (!in)
		return false;
	struct file_key k = { .agent = 0, .dev = BPF_CORE_READ(in, i_sb, s_dev), .ino = BPF_CORE_READ(in, i_ino) };
	u8 *v = bpf_map_lookup_elem(&allowed_socks, &k);
	return v && (*v & DIR_BROKERS);
}

/* current_is_broker tells whether the current process is a registered
 * broker (same tgid and start time). */
static __always_inline bool current_is_broker(struct task_struct *cur)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	u64 *start = bpf_map_lookup_elem(&brokers, &tgid);
	if (!start)
		return false;
	return BPF_CORE_READ(cur, group_leader, start_boottime) / NSEC_PER_TICK == *start;
}

/* claimed_sock tells whether in is a session socket claimed by a live
 * broker other than the current process. */
static __always_inline bool claimed_sock(struct inode *in, u32 *owner)
{
	if (!in)
		return false;
	struct file_key k = { .agent = 0, .dev = BPF_CORE_READ(in, i_sb, s_dev), .ino = BPF_CORE_READ(in, i_ino) };
	struct pts_owner *o = bpf_map_lookup_elem(&broker_socks, &k);
	if (!o || !owner_alive(o))
		return false;
	*owner = o->tgid;
	return (u32)(bpf_get_current_pid_tgid() >> 32) != o->tgid;
}

/* guard_dir decides a change of directory dir's entries; entry is the
 * entry concerned (its inode, when it exists, is checked too: renaming or
 * removing a guarded directory itself). An agent may change nothing in
 * its guarded directories. In a cotty runtime directory nobody but a
 * registered broker and root may bind, link, symlink, rename or remove
 * (removes): the session sockets the person attaches to stay the
 * brokers'. A socket a broker claimed is that broker's alone while it
 * runs: no other process but root, another broker included, may remove,
 * rename or replace it (with or without the daemon). Plain file and
 * directory creation (removes false) stays open there for everyone but
 * agents (logs, metadata, the agent directory). */
static __always_inline int guard_dir(struct inode *dir, struct dentry *entry, bool removes)
{
	struct task_struct *cur = bpf_get_current_task_btf();
	u64 a = agent_of(cur);
	struct inode *target = entry ? BPF_CORE_READ(entry, d_inode) : 0;
	struct inode *hit = 0;
	u32 reason = R_GUARDED_DIR;
	u32 owner = 0;
	if (removes && target && claimed_sock(target, &owner) && BPF_CORE_READ(cur, cred, euid.val) != 0)
		return deny(a, HOOK_INODE, R_BROKER_SOCK, owner, BPF_CORE_READ(target, i_sb, s_dev),
			    BPF_CORE_READ(target, i_ino), BPF_CORE_READ(entry, d_name.name));
	if (a) {
		if (guarded(a, dir))
			hit = dir;
		else if (guarded(a, target))
			hit = target;
	}
	if (!hit && removes) {
		if (broker_dir(dir))
			hit = dir;
		else if (broker_dir(target))
			hit = target;
		if (hit) {
			if (!daemon_alive() || BPF_CORE_READ(cur, cred, euid.val) == 0 || current_is_broker(cur))
				return 0;
			reason = R_BROKER_DIR;
		}
	}
	if (!hit)
		return 0;
	return deny(a, HOOK_INODE, reason, 0, BPF_CORE_READ(hit, i_sb, s_dev), BPF_CORE_READ(hit, i_ino),
		    entry ? BPF_CORE_READ(entry, d_name.name) : 0);
}

/* bind() of a pathname socket creates its inode through vfs_mknod. */
SEC("lsm/inode_mknod")
int BPF_PROG(cotty_inode_mknod, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	return guard_dir(dir, dentry, true);
}

SEC("lsm/inode_create")
int BPF_PROG(cotty_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return guard_dir(dir, dentry, false);
}

SEC("lsm/inode_mkdir")
int BPF_PROG(cotty_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return guard_dir(dir, dentry, false);
}

SEC("lsm/inode_symlink")
int BPF_PROG(cotty_inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name)
{
	return guard_dir(dir, dentry, true);
}

SEC("lsm/inode_link")
int BPF_PROG(cotty_inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	return guard_dir(dir, new_dentry, true);
}

SEC("lsm/inode_unlink")
int BPF_PROG(cotty_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	return guard_dir(dir, dentry, true);
}

SEC("lsm/inode_rmdir")
int BPF_PROG(cotty_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
	return guard_dir(dir, dentry, true);
}

SEC("lsm/inode_rename")
int BPF_PROG(cotty_inode_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	int r = guard_dir(old_dir, old_dentry, true);
	if (r)
		return r;
	return guard_dir(new_dir, new_dentry, true);
}

/* ---- privileges, bpf, signals, scheduling, terminal injection ---- */

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(cotty_bprm_creds_from_file, struct linux_binprm *bprm, struct file *file)
{
	struct task_struct *cur = bpf_get_current_task_btf();
	u64 a = agent_of(cur);
	if (!a)
		return 0;
	/* The capability LSM runs first and has already computed the new
	 * credentials: any gain in uid, gid or permitted capabilities is a
	 * setuid, setgid or file capability exec. */
	const struct cred *nc = BPF_CORE_READ(bprm, cred);
	const struct cred *oc = BPF_CORE_READ(cur, cred);
	u32 neu = BPF_CORE_READ(nc, euid.val), oeu = BPF_CORE_READ(oc, euid.val);
	u32 neg = BPF_CORE_READ(nc, egid.val), oeg = BPF_CORE_READ(oc, egid.val);
	u64 ncap = BPF_CORE_READ(nc, cap_permitted.val), ocap = BPF_CORE_READ(oc, cap_permitted.val);
	if (neu == oeu && neg == oeg && (ncap & ~ocap) == 0)
		return 0;
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	return deny(a, HOOK_EXEC, R_PRIV_EXEC, 0, BPF_CORE_READ(inode, i_sb, s_dev), BPF_CORE_READ(inode, i_ino),
		    BPF_CORE_READ(file, f_path.dentry, d_name.name));
}

SEC("lsm/bpf")
int BPF_PROG(cotty_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	u64 a = current_agent();
	if (!a)
		return 0;
	return deny(a, HOOK_BPF, R_BPF, cmd, 0, 0, 0);
}

SEC("lsm/task_kill")
int BPF_PROG(cotty_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
	u64 a = current_agent();
	if (!a)
		return 0;
	if (agent_of(p) == a)
		return 0;
	return deny(a, HOOK_KILL, R_OTHER_TASK, BPF_CORE_READ(p, tgid), 0, sig, 0);
}

/* other_task denies agents a change to a task outside the agent (resource
 * limits through prlimit, nice, I/O priority, scheduler). */
static __always_inline int other_task(struct task_struct *p, u32 what)
{
	u64 a = current_agent();
	if (!a)
		return 0;
	if (agent_of(p) == a)
		return 0;
	return deny(a, HOOK_TASK_SET, R_OTHER_TASK, BPF_CORE_READ(p, tgid), 0, what, 0);
}

SEC("lsm/task_setrlimit")
int BPF_PROG(cotty_task_setrlimit, struct task_struct *p, unsigned int resource, struct rlimit *new_rlim)
{
	return other_task(p, 1);
}

SEC("lsm/task_setnice")
int BPF_PROG(cotty_task_setnice, struct task_struct *p, int nice)
{
	return other_task(p, 2);
}

SEC("lsm/task_setioprio")
int BPF_PROG(cotty_task_setioprio, struct task_struct *p, int ioprio)
{
	return other_task(p, 3);
}

SEC("lsm/task_setscheduler")
int BPF_PROG(cotty_task_setscheduler, struct task_struct *p)
{
	return other_task(p, 4);
}

/* F_SETOWN makes the kernel send SIGIO (or the F_SETSIG signal) to any
 * process, without task_kill; O_ASYNC on a terminal makes it send SIGIO
 * to the terminal's foreground process group by itself (the person's
 * client, outside the agent): refused to agents, with F_SETSIG. */
SEC("lsm/file_fcntl")
int BPF_PROG(cotty_file_fcntl, struct file *file, unsigned int cmd, unsigned long arg)
{
	if (cmd == F_SETFL) {
		if (!(arg & O_ASYNC))
			return 0;
	} else if (cmd == F_SETSIG) {
		if (arg == 0)
			return 0; /* back to plain SIGIO */
	} else if (cmd != F_SETOWN && cmd != F_SETOWN_EX) {
		return 0;
	}
	if (cmd == F_SETOWN && arg == 0)
		return 0; /* clears the owner */
	u64 a = current_agent();
	if (!a)
		return 0;
	return deny(a, HOOK_FCNTL, R_SIGIO, 0, 0, cmd, 0);
}

static __always_inline int ioctl_rule(unsigned int cmd)
{
	u32 reason;
	if (cmd == TIOCSTI || cmd == TIOCLINUX)
		reason = R_TIOCSTI;
	else if (cmd == FIOSETOWN || cmd == SIOCSPGRP || cmd == FIOASYNC)
		reason = R_SIGIO;
	else
		return 0;
	u64 a = current_agent();
	if (!a)
		return 0;
	return deny(a, HOOK_IOCTL, reason, 0, 0, cmd, 0);
}

SEC("lsm/file_ioctl")
int BPF_PROG(cotty_file_ioctl, struct file *file, unsigned int cmd, unsigned long arg)
{
	return ioctl_rule(cmd);
}

/* 32-bit ioctl on a 64-bit kernel (Linux 6.8 and later route it here
 * instead of file_ioctl). The daemon skips this program on kernels
 * without the hook. */
SEC("lsm/file_ioctl_compat")
int BPF_PROG(cotty_file_ioctl_compat, struct file *file, unsigned int cmd, unsigned long arg)
{
	return ioctl_rule(cmd);
}
