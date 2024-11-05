package main

import (
	"fmt"
	"os"
	"crypto/sha256"
	"io"
	"path/filepath"
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

func appendLog(filename string, text string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(text); err != nil {
		return err
	}

	return nil
}

func log_check(content string, logfile string) {
	err := appendLog(logfile, content)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error appending content to logfile (\033[0;36m%s\033[0m): %s\n", logfile, err)
		return
	}
}

// O(log(n)) Complexity binary search-based verification with recursion
func binary_search_verification(base string, target string, hashExclusions []string, permExclusions []string) {
	baseFiles := make(map[string]string)

	filepath.WalkDir(base, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("\033[31m[FAIL]\033[0m Error accessing path (\033[0;36m%s\033[0m): %s\n", path, err)
			return err
		}

		if !info.IsDir() {
			relativePath, _ := filepath.Rel(base, path)
			baseFiles[relativePath] = checksum(path)
		}
		return nil
	})

	filepath.WalkDir(target, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("\033[31m[FAIL]\033[0m Error accessing path (\033[0;36m%s\033[0m): %s\n", path, err)
			return err
		}

		if !info.IsDir() {
			relativePath, _ := filepath.Rel(target, path)

			// Check if the current file is in the exclusion list
			if contains(hashExclusions, relativePath) {
				return nil
			}

			targetChecksum := checksum(path)
			if baseChecksum, found := baseFiles[relativePath]; found {
				if baseChecksum == targetChecksum {
					fmt.Printf("\033[32m[OK]\033[0m File matched (\033[0;36m%s/%s\033[0m --> \033[0;36m%s/%s\033[0m)\n", base, relativePath, target, relativePath)
				} else {
					fmt.Printf("\033[31m[ALERT]\033[0m Checksum conflict (\033[0;36m%s/%s\033[0m)\n", target, relativePath)
					log_check(target + "/" + relativePath + "\n", "conflicts.log")
				}
			} else {
				fmt.Printf("\033[31m[ALERT]\033[0m File exists in target but not in base: (\033[0;36m%s/%s\033[0m)\n", target, relativePath)
				log_check(target + "/" + relativePath + "\n", "target_specific.log")
			}
		}
		return nil
	})

	for relativePath := range baseFiles {
		targetPath := filepath.Join(target, relativePath)
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in base but not in target (\033[0;36m%s/%s\033[0m)\n", base, relativePath)
			log_check(base + "/" + relativePath + "\n", "base_specific.log")
		}
	}
}

func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

// Help and usage menu
func help() {
	fmt.Printf("Usage: ./fenrir [OPTION1] [ARGUMENT1] ... [OPTIONn] [ARGUMENTn]\n")
	fmt.Printf("\nOptions:\n")
	fmt.Printf("	-b, Declares base directory (REQUIRES TARGET)\n")
	fmt.Printf("	-t, Declares target directory (REQUIRES BASE)\n")
	fmt.Printf("	-xh, Excludes hashes from comparison using specified file\n")
	fmt.Printf("	-xp, Excludes permissions from comparison using specified file\n")
	fmt.Printf("	-c, Clears all log files\n")
	fmt.Printf("	-h, Shows usage menu\n")
	fmt.Printf("\nFormat:\n")
	fmt.Printf("	./fenrir -h\n")
	fmt.Printf("	./fenrir -b <BASE> -t <TARGET>\n")
	fmt.Printf("	./fenrir -t <TARGET> -b <BASE>\n")
	fmt.Printf("	./fenrir -c\n")
	fmt.Printf("\nExamples:\n")
	fmt.Printf("	./fenrir -b ./simulation/base_dir -t ./simulation/target_dir\n")
}

func clean() {
	var logs = []string{
		"conflicts.log",
		"base_specific.log",
		"target_specific.log",
	}

	for _, log := range logs {
		if _, err := os.Stat(log); err == nil {
			os.Remove(log)
		}
	}
}

// Main function and argument logic
// Main function and argument logic
func main() {
    if len(os.Args) < 2 {
        help()
        return
    }

    var base, target string
    var clearLogs bool
    var hashExclusions, permExclusions []string

    for i := 1; i < len(os.Args); i++ {
        switch os.Args[i] {
        case "-b":
            if i+1 < len(os.Args) {
                base = os.Args[i+1]
                i++ // Skip the next argument as it's the base directory
            } else {
                help()
                return
            }
        case "-t":
            if i+1 < len(os.Args) {
                target = os.Args[i+1]
                i++ // Skip the next argument as it's the target directory
            } else {
                help()
                return
            }
        case "-c":
            clearLogs = true
        case "-xh":
            if i+1 < len(os.Args) {
                hashExclusions = append(hashExclusions, os.Args[i+1])
                i++ // Skip the next argument
            }
        case "-xp":
            if i+1 < len(os.Args) {
                permExclusions = append(permExclusions, os.Args[i+1])
                i++ // Skip the next argument
            }
        default:
            help()
            return
        }
    }

    if clearLogs {
        clean()
        return
    }

    if base != "" && target != "" {
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

        binary_search_verification(base, target, hashExclusions, permExclusions) // Adjusted call to match the function signature
    } else {
        help()
    }
}
