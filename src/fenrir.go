package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// Retrieve file permissions in octal format
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

// Append a string to a log file
func log_check(content string, logfile string) {
	err := appendLog(logfile, content)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error appending content to logfile (\033[0;36m%s\033[0m): %s\n", logfile, err)
		return
	}
}

// Load hash (xh) and permission (xp) exclusions
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
func verify(base, target, hashExcFile, permExcFile string) {
	hashExclusions, err := load_exclusions(hashExcFile)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error loading hash exclusion file: %s\n", err)
		return
	}
	permExclusions, err := load_exclusions(permExcFile)
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

			if _, excluded := hashExclusions[relativePath]; !excluded {
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
	fmt.Printf("	-xh, Declares hash exclusion file\n")
	fmt.Printf("	-xp, Declares permission exclusion file\n")
	fmt.Printf("	-c, Clears all log files\n")
	fmt.Printf("	-h, Shows usage menu\n")
	fmt.Printf("\nFormat:\n")
	fmt.Printf("	./fenrir -h\n")
	fmt.Printf("	./fenrir -b <BASE> -t <TARGET>\n")
	fmt.Printf("	./fenrir -b <BASE> -t <TARGET> -xh <HASH_EXCLUSIONS> -xp <PERM_EXCLUSIONS>\n")
	fmt.Printf("	./fenrir -c\n")
	fmt.Printf("\nExamples:\n")
	fmt.Printf("	./fenrir -b ./simulation/base_dir -t ./simulation/target_dir -xh exhash.txt -xp experm.txt\n")
}

// Clean all log files from current directory
func clean() {
	var logs = []string{
		"conflicts.log",
		"base_specific.log",
		"target_specific.log",
		"permission_conflicts.log",
	}

	for i := 0; i < len(logs); i++ {
		if _, err := os.Stat(logs[i]); err == nil {
			os.Remove(logs[i])
		}
	}
}

// Main function and argument logic
func main() {
	var base, target, hashExclusions, permExclusions string

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-b":
			if i+1 < len(os.Args) {
				base = os.Args[i+1]
				i++
			}
		case "-t":
			if i+1 < len(os.Args) {
				target = os.Args[i+1]
				i++
			}
		case "-xh":
			if i+1 < len(os.Args) {
				hashExclusions = os.Args[i+1]
				i++
			}
		case "-xp":
			if i+1 < len(os.Args) {
				permExclusions = os.Args[i+1]
				i++
			}
		case "-c":
			clean()
			return
		case "-h":
			help()
			return
		default:
			help()
			return
		}
	}

	if base != "" && target != "" {
		verify(base, target, hashExclusions, permExclusions)
	} else {
		help()
	}
}