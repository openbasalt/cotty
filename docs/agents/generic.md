# Generic profile

Used for any command whose name matches no other profile, and by the
escape matrix. It exposes the project and the common read-only git files,
nothing else from `$HOME`.

```
cotty agent -- bash                       # a confined shell, to look around
cotty agent --rw ~/.cache/mytool -- mytool
```

For a tool you use often, copy `profiles/generic.conf` to
`~/.config/cotty/profiles/NAME.conf`, set `name = NAME`, `command = NAME`,
and list its directories under `[home]`.
