package confine

import (
	"fmt"
	"os"
	"strings"
)

// appArmorUnpriv is the agent's profile (dist/apparmor/cotty).
const appArmorUnpriv = "unpriv_cotty"

// confineAppArmor asks AppArmor to run the program this process executes
// next under unpriv_cotty, when this process runs under cotty's own
// profile (Ubuntu and other systems that restrict user namespaces). Under
// that profile every capability is denied, so the agent cannot use a user
// namespace even when it executes cotty again. Nothing happens without
// AppArmor or under another label.
func confineAppArmor() error {
	label, attr := "", ""
	for _, d := range []string{"/proc/self/attr/apparmor", "/proc/self/attr"} {
		b, err := os.ReadFile(d + "/current")
		if err != nil {
			continue
		}
		label = strings.TrimSpace(strings.TrimRight(string(b), "\x00\n"))
		attr = d + "/exec"
		break
	}
	name, _, _ := strings.Cut(label, " ")
	if name != "cotty" {
		return nil
	}
	// A transition, not a stack: in a stack the cotty profile (unconfined
	// mode) still mediates network access on AppArmor 4.0 (Ubuntu 24.04),
	// which breaks DNS inside. The cotty profile is in unconfined mode, so
	// no_new_privs does not stand in the way of the transition.
	var err error
	for _, req := range []string{"exec " + appArmorUnpriv, "stack " + appArmorUnpriv} {
		if err = writeAttr(attr, req); err == nil {
			return nil
		}
	}
	return fmt.Errorf("apparmor: cannot put the agent under %s (is the profile from dist/apparmor/cotty loaded? sudo apparmor_parser -r /etc/apparmor.d/cotty): %w", appArmorUnpriv, err)
}

func writeAttr(attr, v string) error {
	f, err := os.OpenFile(attr, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte(v))
	return err
}
