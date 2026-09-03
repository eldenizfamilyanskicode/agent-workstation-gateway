//go:build !linux

package main

func runPlatformHelper([]string) (bool, int) { return false, 0 }
