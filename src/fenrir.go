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

///////////////////////////////////////////////////////////
// O(log(n)) Complexity binary search-based verification //
///////////////////////////////////////////////////////////
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
					fmt.Printf("\033[32m[OK]\033[0m File matched (%s/%s --> %s/%s)\n", base, currentFileName, target, targetFilenames[mid])
				} else {
					fmt.Printf("\033[31m[ALERT]\033[0m Checksum mismatch (%s/%s)\n", base, currentFileName)
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
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in base but not in target: (%s/%s)\n", base, currentFileName)
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
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in target but not in base: (%s/%s)\n", target, targetFileName)
		}
	}
}

func help() {
	// Logo
	fmt.Println("=================================")
	fmt.Println("	 ______                _    ")
	fmt.Println("   / ____/__  ____  _____(_)____ ")
	fmt.Println("  / /_  / _ \/ __ \/ ___/ / ___/ ")
	fmt.Println(" / __/ /  __/ / / / /  / / /   ")
	fmt.Println("/_/    \___/_/ /_/_/  /_/_/  ")      
	fmt.Println("=================================")
	fmt.Println()

	// Usage
	fmt.Printf("Usage: ./fenrir [OPTION1] [ARGUMENT1] ... [OPTIONn] [ARGUMENTn]\n")
	fmt.Printf("\nOptions:\n")
	fmt.Printf("	-b, Declares base file (REQUIRES TARGET)\n")
	fmt.Printf("	-t, Declares target file (REQUIRES BASE)\n")
	fmt.Printf("	-h, Shows usage menu\n")
	fmt.Printf("\nFormat:\n")
	fmt.Printf("	./fenrir -h\n")
	fmt.Printf("	./fenrir -b <BASE> -t <TARGET>\n")
	fmt.Printf("\nExamples:\n")
	fmt.Printf("	./fenrir -b ./simulation/base_dir -t ./simulation/target_dir\n")
}

func main() {
	base := "./base_dir"
	target := "./target_dir"

	binary_search_verification(base, target)
}