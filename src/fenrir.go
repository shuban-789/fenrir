package main

import (
	"fmt"
	"os"
	"crypto/sha256"
	"strings"
	"io"
)

func checksum(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("ERROR OPENING FILE (%s): %s\n", filePath, err)
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		fmt.Printf("ERROR WITH HASH GENERATION (%s): %s\n", filePath, err)
		return ""
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

// O(log(n)) Complexity binary search-based verification
func binary_search_verification(base string, target string) {
	basefiles, err := os.ReadDir(base)
	if err != nil {
		fmt.Printf("ERROR READING DIRECTORY (%s): %s\n", base, err)
		return
	}

	targetfiles, err := os.ReadDir(target)
	if err != nil {
		fmt.Printf("ERROR READING DIRECTORY (%s): %s\n", target, err)
		return
	}

	targetFilenames := make([]string, len(targetfiles))
	for i, f := range targetfiles {
		targetFilenames[i] = f.Name()
	}

	for _, entry := range basefiles {
		currentFileName := entry.Name()
		currentChecksum := checksum(base + "/" + currentFileName)
		low, high := 0, len(targetFilenames)-1
		found := false

		for low <= high {
			mid := low + (high-low)/2
			compareResult := strings.Compare(targetFilenames[mid], currentFileName)
			if compareResult == 0 {
				targetChecksum := checksum(target + "/" + targetFilenames[mid])
				if currentChecksum == targetChecksum {
					fmt.Printf("\033[32m[OK]\033[0m File matched: %s\n", currentFileName)
				} else {
					fmt.Printf("\033[31m[ALERT]\033[0m Checksum mismatch: %s\n", currentFileName)
				}
				found = true
				break
			} else if compareResult < 0 {
				low = mid + 1
			} else {
				high = mid - 1
			}
		}

		if !found {
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in base but not in target: %s\n", currentFileName)
		}
	}

	baseFilenames := make([]string, len(basefiles))
	for i, f := range basefiles {
		baseFilenames[i] = f.Name()
	}

	for _, targetFile := range targetfiles {
		targetFileName := targetFile.Name()
		low, high := 0, len(baseFilenames)-1
		found := false

		for low <= high {
			mid := low + (high-low)/2
			compareResult := strings.Compare(baseFilenames[mid], targetFileName)
			if compareResult == 0 {
				found = true
				break
			} else if compareResult < 0 {
				low = mid + 1
			} else {
				high = mid - 1
			}
		}

		if !found {
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in target but not in base: %s\n", targetFileName)
		}
	}
}

func help() {
	fmt.Println("Usage instructions in progress")
}

func main() {
	base := "./base_dir"
	target := "./target_dir"

	binary_search_verification(base, target)
}