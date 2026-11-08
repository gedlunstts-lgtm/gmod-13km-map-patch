//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// waitIfOwnConsole holds the window open when the patcher was started by
// double-clicking it, and returns immediately when it was run from a shell.
//
// GetConsoleProcessList reports how many processes share this console. Run
// from cmd or PowerShell that is at least two - the shell and us. Started
// from Explorer, Windows makes a console just for this process, so the count
// is one, and the window disappears the moment we exit.
func waitIfOwnConsole() {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return
	}
	var pids [8]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if n != 1 {
		return
	}
	fmt.Print("\nPress Enter to close this window.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
