package main

import (
	"fmt"
	"os"
	"crypto/sha256"
	"strings"
	"io"
)

//////////////////////////////////////////////////////
// SHA-256 checksum verification function for files //
//////////////////////////////////////////////////////
func checksum(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("ERROR OPENING FILE (\033[0;36m%s\033[0m): %s\n", filePath, err)
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		fmt.Printf("ERROR WITH HASH GENERATION (\033[0;36m%s\033[0m): %s\n", filePath, err)
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
					fmt.Printf("\033[32m[OK]\033[0m File matched (\033[0;36m%s/%s\033[0m --> \033[0;36m%s/%s\033[0m)\n", base, currentFileName, target, targetFilenames[mid])
				} else {
					fmt.Printf("\033[31m[ALERT]\033[0m Checksum mismatch (\033[0;36m%s/%s\033[0m)\n", base, currentFileName)
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
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in base but not in target: (\033[0;36m%s/%s\033[0m)\n", base, currentFileName)
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
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in target but not in base: (\033[0;36m%s/%s\033[0m)\n", target, targetFileName)
		}
	}
}

/////////////////////////
// Help and usage menu //
/////////////////////////
func help() {
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

//////////////////////////////////////
// Main function and argument logic //
//////////////////////////////////////
func main() {
	if len(os.Args) > 1 {
		if strings.Compare(os.Args[1], "-b") == 0 {
			if len(os.Args) >= 5 && strings.Compare(os.Args[3], "-t") == 0 {
				base := os.Args[2]
				target := os.Args[4]
				binary_search_verification(base, target)
			} else {
				help()
			}
		} else if strings.Compare(os.Args[1], "-t") == 0 {
			if len(os.Args) >= 5 && strings.Compare(os.Args[3], "-b") == 0 {
				target := os.Args[2]
				base := os.Args[4]
				binary_search_verification(base, target)
			} else {
				help()
			}
		} else {
			help()
		}
	} else {
		help()
	}
}
