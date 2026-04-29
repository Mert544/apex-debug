package main

import (
	"fmt"
	"os/exec"
	"os"
)

func runCommand(userInput string) {
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()
}

func readFile(userPath string) ([]byte, error) {
	return os.ReadFile("/data/" + userPath)
}

func unsafePtr(addr uintptr) *int {
	return (*int)(unsafe.Pointer(addr))
}

func main() {
	fmt.Println("Hello")
}
