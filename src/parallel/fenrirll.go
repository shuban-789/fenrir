package main

import (
	"fmt"
	"os"
	"crypto/sha256"
	"strings"
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
func binary_search_verification(base string, target string) {
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

			targetChecksum := checksum(path)
			if baseChecksum, found := baseFiles[relativePath]; found {
				if baseChecksum == targetChecksum {
					fmt.Printf("\033[32m[OK]\033[0m File matched (\033[0;36m%s/%s\033[0m --> \033[0;36m%s/%s\033[0m)\n", base, relativePath, target, relativePath)
				} else {
					fmt.Printf("\033[31m[ALERT]\033[0m Checksum conflict (\033[0;36m%s/%s\033[0m)\n", target, relativePath)
					var conflicts_log = target + "/" + relativePath + "\n"
					log_check(conflicts_log, "conflicts.log")
				}
			} else {
				fmt.Printf("\033[31m[ALERT]\033[0m File exists in target but not in base: (\033[0;36m%s/%s\033[0m)\n", target, relativePath)
				var target_specific_log = target + "/" + relativePath + "\n"
				log_check(target_specific_log, "target_specific.log")
			}
		}
		return nil
	})

	for relativePath, _ := range baseFiles {
		targetPath := filepath.Join(target, relativePath)
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in base but not in target (\033[0;36m%s/%s\033[0m)\n", base, relativePath)
			var base_specific_log = base + "/" + relativePath + "\n"
			log_check(base_specific_log, "base_specific.log")
		}
	}
}

// Help and usage menu
func help() {
	fmt.Printf("Usage: ./fenrir [OPTION1] [ARGUMENT1] ... [OPTIONn] [ARGUMENTn]\n")
	fmt.Printf("\nOptions:\n")
	fmt.Printf("	-b, Declares base directory (REQUIRES TARGET)\n")
	fmt.Printf("	-t, Declares target directory (REQUIRES BASE)\n")
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

	for i := 0; i < len(logs); i++ {
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
		} else if strings.Compare(os.Args[1], "-c") == 0 {
			clean()
		} else {
			help()
		}
	} else {
		help()
	}
}