package main

import (
	"fmt"
	"os"
	"crypto/sha256"
	"strings"
)

func checksum(filePath string) string {
	file, err := os.Open(filePath)
    if err != nil {
        fmt.Println("ERROR OPENING FILE (%s): %s", file, err)
    }
    defer file.Close()

	hash := sha256.New()
  	if _, err := io.Copy(hash, file); err != nil {
    	fmt.Println("ERROR WITH HASH GENERATION (%s): %s", file, err)
  	}

	return hash.Sum(nil)
}

// O(log(n)) Complexity
func binary_search_verification(base string, target string) {
	basefiles, err := os.ReadDir(base)
	if err != nil {
		fmt.Println("ERROR READING DIRECTORY (%s): %s", base, err)
	}

	targetfiles, err := os.ReadDir(target)
	if err != nil {
		fmt.Println("ERROR READING DIRECTORY (%s): %s", target, err)
	}

	for _, entry := range entries {
		current_checksum := checksum(entry.Name())
		low, high := 0, len(targetfiles)-1
		for low <= high {
			mid := low + (high-low)/2
			if targetfiles[mid] == entry.Name() {
				target_checksum := checksum(targetfiles[mid])
				if strings.Compare(current_checksum, targetfiles[mid]) == 0 {
					fmt.Println("[OK] (%s) (%s)", entry.Name(), targetfiles[mid])
				} else {
					fmt.Println("[ALERT] (%s) (%s)", entry.Name(), targetfiles[mid])
				}
			} else if arr[mid] < target {
				low = mid + 1
			} else {
				high = mid - 1
			}
		}

		// Fallback for if file exists on baseline but not target
	}
}

func help() {
	fmt.Println("In progress")
}

func main() {
	fmt.Println("In progress")
}