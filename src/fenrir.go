package main

import (
	"fmt"
	"os"
	"crypto/sha256"
	"strings"
	"io"
)

// SHA-256 checksum verification function for files
func checksum(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error reading file (\033[0;36m%s\033[0m): %s\n", filePath, err)
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error retrieving sha256 hash (\033[0;36m%s\033[0m): %s\n", filePath, err)
		return ""
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func log_check(content string, logfile string) {
	byte_content := []byte(content)
    err := os.WriteFile(logfile, byte_content, 0777)
    if err != nil {
        fmt.Printf("\033[31m[FAIL]\033[0m Error appending content to logfile (\033[0;36m%s\033[0m): %s\n", logfile, err)
		return
    }
}

// O(log(n)) Complexity binary search-based verification
func binary_search_verification(base string, target string) {
	basefiles, err := os.ReadDir(base)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error reading directory (%s): %s\n", base, err)
		return
	}

	targetfiles, err := os.ReadDir(target)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error reading directory (%s): %s\n", target, err)
		return
	}

	targetFilenames := make([]string, 0)
	for _, f := range targetfiles {
		if !f.IsDir() {
			targetFilenames = append(targetFilenames, f.Name())
		}
	}

	for _, entry := range basefiles {
		if entry.IsDir() {
			continue
		}

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
					fmt.Printf("\033[31m[ALERT]\033[0m Checksum conflict (\033[0;36m%s/%s\033[0m)\n", target, targetFilenames[mid])
					var conflicts_log = target + "/" + targetFilenames[mid] + "\n"
					log_check(conflicts_log, "conflicts.log")
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
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in base but not in target (\033[0;36m%s/%s\033[0m)\n", base, currentFileName)
			var base_specific_log = base + "/" + currentFileName + "\n"
			log_check(base_specific_log, "base_specific.log")
		}
	}

	baseFilenames := make([]string, 0)
	for _, f := range basefiles {
		if !f.IsDir() {
			baseFilenames = append(baseFilenames, f.Name())
		}
	}

	for _, targetFile := range targetfiles {
		if targetFile.IsDir() {
			continue
		}
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
			var target_specific_log = target + "/" + targetFileName + "\n"
			log_check(target_specific_log, "target_specific.log")
		}
	}
}

// Help and usage menu
func help() {
	fmt.Printf("Usage: ./fenrir [OPTION1] [ARGUMENT1] ... [OPTIONn] [ARGUMENTn]\n")
	fmt.Printf("\nOptions:\n")
	fmt.Printf("	-b, Declares base directory (REQUIRES TARGET)\n")
	fmt.Printf("	-t, Declares target directory (REQUIRES BASE)\n")
	fmt.Printf("	-h, Shows usage menu\n")
	fmt.Printf("\nFormat:\n")
	fmt.Printf("	./fenrir -h\n")
	fmt.Printf("	./fenrir -b <BASE> -t <TARGET>\n")
	fmt.Printf("\nExamples:\n")
	fmt.Printf("	./fenrir -b ./simulation/base_dir -t ./simulation/target_dir\n")
}

func clean() {
	const logs = [3]string{
		"conflicts.log",
		"base_specific.log",
		"target_specific.log"
	}
	for (i := 0; i < len(logs); i++) {
		if _, err := os.Stat(logs[i]); err == nil {
			os.Remove(logs[i])
		}
	}
}

// Main function and argument logic
func main() {
	if len(os.Args) > 1 {
		if strings.Compare(os.Args[1], "-b") == 0 {
			if len(os.Args) >= 5 && strings.Compare(os.Args[3], "-t") == 0 {
				base := os.Args[2]
				target := os.Args[4]
				conflict_log, conflict_log_err := os.Create("conflicts.log")
				if conflict_log_err != nil {
					fmt.Printf("\033[31m[FAIL]\033[0m Error creating log file (\033[0;36mconflicts.log\033[0m): %s\n", conflict_log_err)
					return
				}
				defer conflict_log.Close()
				base_specific, base_specific_log_err := os.Create("base_specific.log")
				if base_specific_log_err != nil {
					fmt.Printf("\033[31m[FAIL]\033[0m Error creating log file (\033[0;36mbase_specific.log\033[0m): %s\n", base_specific_log_err)
					return
				}
				defer base_specific.Close()
				target_specific, target_specific_log_err := os.Create("target_specific.log")
				if target_specific_log_err != nil {
					fmt.Printf("\033[31m[FAIL]\033[0m Error creating log file (\033[0;36mtarget_specific.log\033[0m): %s\n", target_specific_log_err)
					return
				}
				defer target_specific.Close()
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