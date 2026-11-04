package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
	"github.com/openbasalt/cotty/internal/session"
)

func init() {
	register(command{name: "ls", summary: "list sessions", run: runLs})
}

func runLs(args []string) int {
	dir, err := session.Dir()
	if err != nil {
		return fail("%v", err)
	}
	names, err := session.Names(dir)
	if err != nil {
		return fail("%v", err)
	}
	if len(names) == 0 {
		fmt.Println("no cotty sessions")
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCREATED\tSIZE\tPERSONS\tAGENTS\tSHARED\tPOLICY")
	for _, n := range names {
		p := session.PathsFor(dir, n)
		info, err := sessionInfo(p.Socket)
		if err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
				// The broker is gone: clean up what it left.
				_ = os.Remove(p.Socket)
				_ = os.Remove(p.Meta)
				continue
			}
			fmt.Fprintf(tw, "%s\t(%v)\n", n, err)
			continue
		}
		created := info.Created
		if t, err := time.Parse(time.RFC3339, info.Created); err == nil {
			created = t.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%dx%d\t%d\t%d\t%v\t%s\n", n, created, info.Cols, info.Rows,
			info.Persons, info.Agents, info.Shared, info.Policy)
	}
	_ = tw.Flush()
	return 0
}

func sessionInfo(sock string) (proto.Info, error) {
	var info proto.Info
	cl, err := proto.Dial(sock)
	if err != nil {
		return info, err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cl.Hello(ctx, proto.Hello{Role: proto.RoleInfo, Client: "cotty-ls"}); err != nil {
		return info, err
	}
	err = cl.Call(ctx, "info", nil, &info)
	return info, err
}
