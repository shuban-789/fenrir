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

// Append a string to a log file
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

// Parse exclusions from files
func loadExclusions(filename string) (map[string]bool, error) {
	exclusions := make(map[string]bool)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var line string
	for {
		_, err := fmt.Fscanln(file, &line)
		if err != nil {
			break
		}
		exclusions[line] = true
	}
	return exclusions, nil
}

// Hash verification algorithm with permission checks
func verify(base string, target string, ignoreHashFile, ignorePermFile string) {
	var ignoreHashes, ignorePerms map[string]bool
	var err error

	if ignoreHashFile != "" {
		ignoreHashes, err = loadExclusions(ignoreHashFile)
		if err != nil {
			fmt.Printf("\033[31m[FAIL]\033[0m Error loading hash exclusion file: %s\n", err)
			return
		}
	}
	if ignorePermFile != "" {
		ignorePerms, err = loadExclusions(ignorePermFile)
		if err != nil {
			fmt.Printf("\033[31m[FAIL]\033[0m Error loading permission exclusion file: %s\n", err)
			return
		}
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

			if ignoreHashes[relativePath] {
				return nil
			}

			targetChecksum := checksum(path)
			targetPermissions := get_permissions(path)
			if baseFile, found := baseFiles[relativePath]; found {
				if baseFile.checksum == targetChecksum {
					fmt.Printf("\033[32m[OK]\033[0m File matched (\033[0;36m%s/%s\033[0m --> \033[0;36m%s/%s\033[0m)\n", base, relativePath, target, relativePath)
				} else {
					fmt.Printf("\033[31m[ALERT]\033[0m Checksum conflict (\033[0;36m%s/%s\033[0m)\n", target, relativePath)
					appendLog("conflicts.log", target+"/"+relativePath+"\n")
				}

				// Permission comparison if not ignored
				if !ignorePerms[relativePath] && baseFile.permissions != targetPermissions {
					fmt.Printf("\033[31m[ALERT]\033[0m Permission conflict (\033[0;36m%s/%s\033[0m): (base: \033[0;36m%o\033[0m, target: \033[0;36m%o\033[0m)\n", target, relativePath, baseFile.permissions, targetPermissions)
					appendLog("permission_conflicts.log", target+"/"+relativePath+"\n")
				} else {
					fmt.Printf("\033[32m[OK]\033[0m Permissions matched (\033[0;36m%s/%s\033[0m --> \033[0;36m%s/%s\033[0m)\n", base, relativePath, target, relativePath)
				}
			} else {
				fmt.Printf("\033[31m[ALERT]\033[0m File exists in target but not in base: (\033[0;36m%s/%s\033[0m)\n", target, relativePath)
				appendLog("target_specific.log", target+"/"+relativePath+"\n")
			}
		}
		return nil
	})

	for relativePath := range baseFiles {
		targetPath := filepath.Join(target, relativePath)
		if _, err := os.Stat(targetPath); os.IsNotExist(err) && !ignoreHashes[relativePath] {
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in base but not in target (\033[0;36m%s/%s\033[0m)\n", base, relativePath)
			appendLog("base_specific.log", base+"/"+relativePath+"\n")
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
	fmt.Printf("	-xh <file>, File for ignored hash comparisons\n")
	fmt.Printf("	-xp <file>, File for ignored permission comparisons\n")
	fmt.Printf("	-h, Shows usage menu\n")
	fmt.Printf("\nFormat:\n")
	fmt.Printf("	./fenrir -h\n")
	fmt.Printf("	./fenrir -b <BASE> -t <TARGET>\n")
	fmt.Printf("	./fenrir -t <TARGET> -b <BASE>\n")
	fmt.Printf("	./fenrir -b <BASE> -t <TARGET> -xh <HASHEXCFILE> -xp <PERMEXCFILE>\n")
	fmt.Printf("	./fenrir -c\n")
	fmt.Printf("\nExamples:\n")
	fmt.Printf("	./fenrir -b ./simulation/base_dir -t ./simulation/target_dir\n")
	fmt.Printf("	./fenrir -b ./simulation/base_dir -t ./simulation/target_dir -xh exlcusions.txt\n")
	fmt.Printf("	./fenrir -b ./simulation/base_dir -t ./simulation/target_dir -xp exlcusions.txt\n")
}

// Clean log files
func clean() {
	logs := []string{"conflicts.log", "base_specific.log", "target_specific.log", "permission_conflicts.log"}
	for _, log := range logs {
		if _, err := os.Stat(log); err == nil {
			os.Remove(log)
		}
	}
}

// Main function and argument logic
func main() {
	var base, target, ignoreHashFile, ignorePermFile string

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-b":
			base = os.Args[i+1]
			i++
		case "-t":
			target = os.Args[i+1]
			i++
		case "-xh":
			ignoreHashFile = os.Args[i+1]
			i++
		case "-xp":
			ignorePermFile = os.Args[i+1]
			i++
		case "-c":
			clean()
			return
		case "-h":
			help()
			return
		}
	}

	if base != "" && target != "" {
		verify(base, target, ignoreHashFile, ignorePermFile)
	} else {
		help()
	}
}
