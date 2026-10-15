//go:build !linux

package main

import "log"

func serveWG([]string) { log.Fatal("wg: Linux only") }
