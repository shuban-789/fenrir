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

func get_permissions(filePath string) int32 {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error reading file (\033[0;36m%s\033[0m): %s\n", filePath, err)
		return 0
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error retrieving file info (\033[0;36m%s\033[0m): %s\n", filePath, err)
		return 0
	}

	return int32(fileInfo.Mode().Perm())
}

// Append a string to one of the log files 
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

func load_exclusions(filePath string) (map[string]bool, error) {
	exclusions := make(map[string]bool)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		exclusions[scanner.Text()] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return exclusions, nil
}

// Hash verification algorithm with permission checks
func verify(base, target string, fexcfile string, pexcfile string) {
	fileExclusions, err := load_exclusions(fexcfile)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error loading hash exclusion file: %s\n", err)
		return
	}
	permExclusions, err := load_exclusions(pexcfile)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error loading permission exclusion file: %s\n", err)
		return
	}

	baseFiles := make(map[string]struct {
		checksum    string
		permissions int32
	})

	filepath.WalkDir(base, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("\033[31m[FAIL]\033[0m Error accessing path (\033[0;36m%s\033[0m): %s\n", path, err)
			return err
		}

		if !info.IsDir() {
			relativePath, _ := filepath.Rel(base, path)
			baseFiles[relativePath] = struct {
				checksum    string
				permissions int32
			}{
				checksum:    checksum(path),
				permissions: get_permissions(path),
			}
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

			if _, excluded := fileExclusions[relativePath]; !excluded {
				targetChecksum := checksum(path)
				if baseFile, found := baseFiles[relativePath]; found && baseFile.checksum != targetChecksum {
					fmt.Printf("\033[31m[ALERT]\033[0m Checksum conflict (\033[0;36m%s/%s\033[0m)\n", target, relativePath)
					log_check(target+"/"+relativePath+"\n", "conflicts.log")
				}
			}

			if _, excluded := permExclusions[relativePath]; !excluded {
				targetPermissions := get_permissions(path)
				if baseFile, found := baseFiles[relativePath]; found && baseFile.permissions != targetPermissions {
					fmt.Printf("\033[31m[ALERT]\033[0m Permission conflict (\033[0;36m%s/%s\033[0m): (base: \033[0;36m%o\033[0m, target: \033[0;36m%o\033[0m)\n", target, relativePath, baseFile.permissions, targetPermissions)
					log_check(target+"/"+relativePath+"\n", "permission_conflicts.log")
				}
			}
		}
		return nil
	})

	for relativePath := range baseFiles {
		targetPath := filepath.Join(target, relativePath)
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in base but not in target (\033[0;36m%s/%s\033[0m)\n", base, relativePath)
			log_check(base+"/"+relativePath+"\n", "base_specific.log")
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
				permission_conflict_log, permission_conflict_log_err := os.Create("permission_conflicts.log")
				if permission_conflict_log_err != nil {
					fmt.Printf("\033[31m[FAIL]\033[0m Error creating log file (\033[0;36mpermission_conflicts.log\033[0m): %s\n", permission_conflict_log_err)
					return
				}
				defer permission_conflict_log.Close()
				verify(base, target, "", "")
			} else {
				help()
			}
		} else if strings.Compare(os.Args[1], "-t") == 0 {
			if len(os.Args) >= 5 && strings.Compare(os.Args[3], "-b") == 0 {
				target := os.Args[2]
				base := os.Args[4]
				verify(base, target, "", "")
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