//go:build !windows

package main

// Only Windows loses the window on exit; everywhere else the shell stays.
func waitIfOwnConsole() {}
