package daemon

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// HookCheck compares one LSM hook's signature in the running kernel's BTF
// with the arguments bpf/guard.bpf.c reads (by position).
type HookCheck struct {
	Hook      string `json:"hook"`
	Signature string `json:"signature"` // as the kernel declares bpf_lsm_<hook>
	Want      string `json:"want"`      // the leading arguments the program uses
	OK        bool   `json:"ok"`
	Optional  bool   `json:"optional,omitempty"` // the guard runs without it (not attached when missing)
}

// usedArgs lists, per hook, the argument types the programs rely on, in
// order (const and other qualifiers ignored). Trailing kernel arguments
// the programs do not read are allowed.
var usedArgs = []struct {
	hook     string
	args     []string
	optional bool
}{
	{"task_alloc", []string{"struct task_struct *"}, false},
	{"bprm_creds_for_exec", []string{"struct linux_binprm *"}, false},
	{"bprm_creds_from_file", []string{"struct linux_binprm *", "struct file *"}, false},
	{"ptrace_access_check", []string{"struct task_struct *", "unsigned int"}, false},
	{"file_open", []string{"struct file *"}, false},
	{"socket_post_create", []string{"struct socket *", "int", "int", "int", "int"}, false},
	{"unix_stream_connect", []string{"struct sock *", "struct sock *", "struct sock *"}, false},
	{"unix_may_send", []string{"struct socket *", "struct socket *"}, false},
	{"bpf", []string{"int", "union bpf_attr *", "unsigned int"}, false},
	{"task_kill", []string{"struct task_struct *", "struct kernel_siginfo *", "int", "struct cred *"}, false},
	{"file_ioctl", []string{"struct file *", "unsigned int", "long unsigned int"}, false},
	{"file_ioctl_compat", []string{"struct file *", "unsigned int", "long unsigned int"}, true},
	{"file_receive", []string{"struct file *"}, false},
	{"file_fcntl", []string{"struct file *", "unsigned int", "long unsigned int"}, false},
	{"inode_mknod", []string{"struct inode *", "struct dentry *"}, false},
	{"inode_create", []string{"struct inode *", "struct dentry *"}, false},
	{"inode_mkdir", []string{"struct inode *", "struct dentry *"}, false},
	{"inode_symlink", []string{"struct inode *", "struct dentry *"}, false},
	{"inode_link", []string{"struct dentry *", "struct inode *", "struct dentry *"}, false},
	{"inode_unlink", []string{"struct inode *", "struct dentry *"}, false},
	{"inode_rmdir", []string{"struct inode *", "struct dentry *"}, false},
	{"inode_rename", []string{"struct inode *", "struct dentry *", "struct inode *", "struct dentry *"}, false},
	{"task_setrlimit", []string{"struct task_struct *"}, false},
	{"task_setnice", []string{"struct task_struct *"}, false},
	{"task_setioprio", []string{"struct task_struct *"}, false},
	{"task_setscheduler", []string{"struct task_struct *"}, false},
}

// CheckHooks reads the kernel's BTF (no BPF is loaded; any user can run
// it) and checks every hook the guard attaches to.
func CheckHooks() ([]HookCheck, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}
	var out []HookCheck
	for _, u := range usedArgs {
		hc := HookCheck{Hook: u.hook, Want: strings.Join(u.args, ", "), Optional: u.optional}
		var fn *btf.Func
		if err := spec.TypeByName("bpf_lsm_"+u.hook, &fn); err != nil {
			hc.Signature = "missing: " + err.Error()
			out = append(out, hc)
			continue
		}
		proto, ok := fn.Type.(*btf.FuncProto)
		if !ok {
			hc.Signature = "not a function"
			out = append(out, hc)
			continue
		}
		var params []string
		for _, p := range proto.Params {
			tn := typeName(p.Type, true)
			if !strings.HasSuffix(tn, "*") {
				tn += " "
			}
			params = append(params, strings.TrimSpace(tn+p.Name))
		}
		hc.Signature = typeName(proto.Return, true) + " " + u.hook + "(" + strings.Join(params, ", ") + ")"
		hc.OK = len(proto.Params) >= len(u.args)
		for i := 0; hc.OK && i < len(u.args); i++ {
			hc.OK = typeName(proto.Params[i].Type, false) == u.args[i]
		}
		out = append(out, hc)
	}
	return out, nil
}

// typeName renders a BTF type the way C declares it; without
// qualifiers, const and volatile are dropped.
func typeName(t btf.Type, qualifiers bool) string {
	switch v := t.(type) {
	case nil:
		return "void"
	case *btf.Void:
		return "void"
	case *btf.Int:
		return v.Name
	case *btf.Typedef:
		return v.Name
	case *btf.Struct:
		return "struct " + v.Name
	case *btf.Union:
		return "union " + v.Name
	case *btf.Enum:
		return "enum " + v.Name
	case *btf.Fwd:
		return v.Kind.String() + " " + v.Name
	case *btf.Pointer:
		return typeName(v.Target, qualifiers) + " *"
	case *btf.Const:
		if qualifiers {
			return "const " + typeName(v.Type, qualifiers)
		}
		return typeName(v.Type, qualifiers)
	case *btf.Volatile:
		return typeName(v.Type, qualifiers)
	case *btf.Restrict:
		return typeName(v.Type, qualifiers)
	case *btf.TypeTag:
		return typeName(v.Type, qualifiers)
	}
	return fmt.Sprintf("%v", t)
}
