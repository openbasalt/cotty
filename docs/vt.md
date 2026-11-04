# Terminal emulator library: charmbracelet/x/vt

Decision (WP-A, 2026-11-03): the broker's screen model uses
`github.com/charmbracelet/x/vt` v0.1.0. `hinshun/vt10x` was the fallback
named in the plan and is not used.

## How it was compared

`tools/vteval` (its own Go module) runs real programs in a PTY (100x30), records every byte
they print up to a snapshot point, and replays the recording into both
libraries and into tmux, the oracle (`tmux capture-pane -p` on a pane that
cats the recording with `stty raw`). It counts the rows each library
renders differently from tmux and checks the cursor. Scenarios: bash with a
coloured prompt, `ls --color`, wide and combining characters, a 250
character line that wraps; `seq 1 500` (scrolling); zsh line editing
(C-a, cursor keys, a multi-line `for`); vim with syntax colours and line
numbers, insert and half-page scroll; less with paging and a search; htop;
`git log --graph --decorate` with colours, and `git log --stat` through
`less -R`. A fuzz mode feeds 3000 random streams of 2000 tokens biased
towards escape sequences to both libraries.

Run on a Fedora 44 lab host (tmux 3.5):

| scenario        | bytes | x/vt rows off | vt10x rows off |
|-----------------|-------|---------------|----------------|
| bash-ls-colours | 4377  | 1 (see below) | 1              |
| bash-seq-scroll | 2492  | 0             | 0              |
| zsh-zle         | 1128  | 0             | 0              |
| vim-insert      | 8250  | 0             | 0              |
| less-scroll     | 9525  | 0             | 0              |
| htop            | 7425  | 0             | 0              |
| git-log-graph   | 2698  | 0             | 0              |
| git-log-pager   | 2171  | 0             | 0              |

The one differing row is a line with CJK characters, an emoji, a combining
accent and a tab. tmux keeps the tab character in captured text and the
harness expands it with an approximate width table, so the expected text is
itself off by one column; x/vt places the text after the tab where a
terminal does. vt10x puts each wide character in a single cell, so
everything after them on the row is shifted left (four columns short at
the tab in this row).

Fuzz: x/vt panicked on 8 of 3000 streams, vt10x on none. The minimal input
is `ESC [ ; 99 r ESC [ S` (a scroll region whose bottom is below the
screen, then scroll up): an index out of range in ultraviolet's
`DeleteLineArea`. Any program in the session can print that.

## Why x/vt anyway

- Correct widths for wide characters and grapheme clusters (agents read
  CJK file names, emoji in git logs, box drawing).
- A scrollback buffer, which the `since` read is built on; vt10x has none.
- Hooks the broker needs: OSC handlers (`RegisterOscHandler(133, ...)` for
  shell integration marks), alternate screen and mode callbacks (the attach
  snapshot restores DECCKM, bracketed paste and mouse modes).
- Maintained (2026); vt10x's last change is from 2022.

## What the broker does about its gaps

- Panics: `Model.Write` and `Model.Resize` recover, rebuild an empty
  emulator and count the reset (`TestModelRecoversFromPanic` replays the
  minimal input and the fuzz streams). The person's raw stream is not
  affected; the agent sees a blank screen until the program redraws. Worth
  an upstream report.
- Close race: `Emulator.Close` writes a field that `Read` reads without a
  lock; the broker ends the reply reader by closing the reply pipe instead.
- Soft wraps are not recorded. The broker derives `wrapped` from content: a
  row is wrapped when its last column is written and the next row is not
  empty. A line that is exactly as wide as the screen and followed by
  another line reads as wrapped; joining such rows is harmless for masking
  (it only joins more text) and the flags are reported, not applied, in
  `screen` and `since`.
- Scrollback size: the broker drains the emulator's scrollback into its own
  buffer after every write, with absolute line numbers, so `since` cursors
  survive the emulator's limit and private mode can mark committed lines.
- Private mode taint: x/vt keeps no identity for rows, so the model marks
  cells instead. The mark lives in the cell's hyperlink parameters, which
  the emulator copies with the cell whatever moves it: scrolling into
  the scrollback, insert and delete line, reverse index, scroll up and
  down, scroll regions, insert and delete character. The mark starts with
  a C0 byte, which x/vt's OSC parser drops inside a string, so a program
  cannot set it with OSC 8; the person's snapshot removes it before
  rendering. When private mode starts every cell on screen gets a "seen
  before" mark; after each piece of output during private mode, every
  row with a visible cell that lacks it (text written since) gets the
  private mark on all its cells. A cell loses the mark only when
  something is written over it or it is erased, and a row reads
  `[private]` while any of its cells is marked, so it shows again only
  once every column was rewritten or erased: overwriting it column by
  column does not tell the length of what it held. Lines that leave the
  screen while marked, or during private mode, are committed as
  `[private]`. Rows are never compared by text, so there is no answer to
  "is this text a private row". During private mode output is cut before
  each mode set or reset (`CSI ? Pm h` or `CSI ? Pm l`), so text written to the
  main screen in the same chunk as the switch to the alternate screen is
  marked before the switch; a switch the cut misses marks the main screen
  when it is shown again. x/vt does not re-wrap rows on a resize (it cuts
  or pads them), so marks survive resizes.
- Queries (DA, DSR): the emulator's answers go to the PTY only while no
  person is attached; with a person attached their real terminal answers.
