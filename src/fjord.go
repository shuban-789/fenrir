package main

import (
	"fmt"
	"os"
	"crypto/sha256"
	"io"
	"path/filepath"
)

// SHA-256 checksum verification function for files (self explanatory)
func checksum(filePath string) string {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error converting to absolute path (\033[0;36m%s\033[0m): %s\n", filePath, err)
		return ""
	}
	file, err := os.Open(absPath)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error reading file (\033[0;36m%s\033[0m): %s\n", absPath, err)
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error retrieving sha256 hash (\033[0;36m%s\033[0m): %s\n", absPath, err)
		return ""
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

// Get permissions of a file (self explanatory)
func get_permissions(filePath string) int32 {
    absPath, err := filepath.Abs(filePath)
    if err != nil {
        fmt.Printf("\033[31m[FAIL]\033[0m Error converting to absolute path (\033[0;36m%s\033[0m): %s\n", filePath, err)
        return 0
    }
    file, err := os.Open(absPath)
    if err != nil {
        fmt.Printf("\033[31m[FAIL]\033[0m Error reading file (\033[0;36m%s\033[0m): %s\n", absPath, err)
        return 0
    }
    defer file.Close()

    fileInfo, err := file.Stat()
    if err != nil {
        fmt.Printf("\033[31m[FAIL]\033[0m Error retrieving file info (\033[0;36m%s\033[0m): %s\n", absPath, err)
        return 0
    }

    return int32(fileInfo.Mode().Perm())
}

// Append a string to a log file (self explanatory)
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
func loadExclusions(filename string, signal int) (map[string]bool, error) {
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
		absPath, err := filepath.Abs(line)
		if err != nil {
			fmt.Printf("\033[31m[FAIL]\033[0m Error converting to absolute path: %s\n", err)
			continue
		}
        if signal == 0 {
		    fmt.Printf("\033[33m[INFO]\033[0m Hash exclusion loaded (\033[0;36m%s/%s\033[0m)\n", absPath)
        } else if signal == 1 {
            fmt.Printf("\033[33m[INFO]\033[0m Permission exclusion loaded (\033[0;36m%s/%s\033[0m)\n", absPath)
        }
		exclusions[absPath] = true
	}
	return exclusions, nil
}

// Hash verification algorithm with permission checks
func verify(base string, target string, ignoreHashFile, ignorePermFile string) {
	ignoreHashes := make(map[string]bool)
	ignorePerms := make(map[string]bool)

	if ignoreHashFile != "" {
		var err error
		ignoreHashes, err = loadExclusions(ignoreHashFile, 0)
		if err != nil {
			fmt.Printf("\033[31m[FAIL]\033[0m Error loading hash exclusion file: %s\n", err)
			return
		}
	}
	if ignorePermFile != "" {
		var err error
		ignorePerms, err = loadExclusions(ignorePermFile, 1)
		if err != nil {
			fmt.Printf("\033[31m[FAIL]\033[0m Error loading permission exclusion file: %s\n", err)
			return
		}
	}

	baseFiles := make(map[string]struct {
		checksum    string
		permissions int32
	})

	baseAbs, err := filepath.Abs(base)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error converting base path to absolute: %s\n", err)
		return
	}

	targetAbs, err := filepath.Abs(target)
	if err != nil {
		fmt.Printf("\033[31m[FAIL]\033[0m Error converting target path to absolute: %s\n", err)
		return
	}

    // break --> base file search
	filepath.WalkDir(baseAbs, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("\033[31m[FAIL]\033[0m Error accessing path (\033[0;36m%s\033[0m): %s\n", path, err)
			return err
		}

		if !info.IsDir() {
			absPath, _ := filepath.Abs(path)
			relativePath, _ := filepath.Rel(baseAbs, absPath)
			baseFiles[relativePath] = struct {
				checksum    string
				permissions int32
			}{
				checksum:    checksum(absPath),
				permissions: get_permissions(absPath),
			}
		}
		return nil
	})

    // break --> target file search
	filepath.WalkDir(targetAbs, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("\033[31m[FAIL]\033[0m Error accessing path (\033[0;36m%s\033[0m): %s\n", path, err)
			return err
		}

		if !info.IsDir() {
			absPath, _ := filepath.Abs(path)
			relativePath, _ := filepath.Rel(targetAbs, absPath)

			if ignoreHashes[absPath] {
				fmt.Printf("\033[33m[INFO]\033[0m Skipping hash check for excluded file (\033[0;36m%s\033[0m)\n", absPath)
				return nil
			}

			targetChecksum := checksum(absPath)
			targetPermissions := get_permissions(absPath)

			if baseFile, found := baseFiles[relativePath]; found {
				if baseFile.checksum == targetChecksum {
					fmt.Printf("\033[32m[OK]\033[0m File matched (\033[0;36m%s/%s\033[0m --> \033[0;36m%s/%s\033[0m)\n", baseAbs, relativePath, targetAbs, relativePath)
				} else {
					fmt.Printf("\033[31m[ALERT]\033[0m Checksum conflict (\033[0;36m%s/%s\033[0m)\n", targetAbs, relativePath)
					appendLog("conflicts.log", targetAbs+"/"+relativePath+"\n")
				}

				if ignorePerms[absPath] {
					fmt.Printf("\033[33m[INFO]\033[0m Skipping permission check for excluded file (\033[0;36m%s\033[0m)\n", absPath)
				} else if baseFile.permissions != targetPermissions {
					fmt.Printf("\033[31m[ALERT]\033[0m Permission conflict (\033[0;36m%s/%s\033[0m): (base: \033[0;36m%o\033[0m, target: \033[0;36m%o\033[0m)\n", targetAbs, relativePath, baseFile.permissions, targetPermissions)
					appendLog("permission_conflicts.log", targetAbs+"/"+relativePath+"\n")
				} else {
					fmt.Printf("\033[32m[OK]\033[0m Permissions matched (\033[0;36m%s/%s\033[0m --> \033[0;36m%s/%s\033[0m)\n", baseAbs, relativePath, targetAbs, relativePath)
				}
			} else {
				fmt.Printf("\033[31m[ALERT]\033[0m File exists in target but not in base (\033[0;36m%s/%s\033[0m)\n", targetAbs, relativePath)
				appendLog("target_specific.log", targetAbs+"/"+relativePath+"\n")
			}
		}
		return nil
	})

	for relativePath := range baseFiles {
		targetPath := filepath.Join(targetAbs, relativePath)
		if _, err := os.Stat(targetPath); os.IsNotExist(err) && !ignoreHashes[targetPath] {
			fmt.Printf("\033[31m[ALERT]\033[0m File exists in base but not in target (\033[0;36m%s/%s\033[0m)\n", baseAbs, relativePath)
			appendLog("base_specific.log", baseAbs+"/"+relativePath+"\n")
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
}

// Main function to parse command line arguments and initiate verification
func main() {
	var base, target, ignoreHashFile, ignorePermFile string
	clearLogs := false

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-b":
			if i+1 < len(os.Args) {
				base = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -b option requires an argument")
				help()
				return
			}
		case "-t":
			if i+1 < len(os.Args) {
				target = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -t option requires an argument")
				help()
				return
			}
		case "-c":
			clearLogs = true
		case "-xh":
			if i+1 < len(os.Args) {
				ignoreHashFile = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -xh option requires an argument")
				help()
				return
			}
		case "-xp":
			if i+1 < len(os.Args) {
				ignorePermFile = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -xp option requires an argument")
				help()
				return
			}
		default:
			fmt.Printf("Unknown option: %s\n", os.Args[i])
			help()
			return
		}
	}

	if clearLogs {
		logFiles := []string{"conflicts.log", "permission_conflicts.log", "target_specific.log", "base_specific.log"}
		for _, logFile := range logFiles {
			err := os.Remove(logFile)
			if err != nil && !os.IsNotExist(err) {
				fmt.Printf("\033[31m[FAIL]\033[0m Error clearing log file %s: %s\n", logFile, err)
			} else {
				fmt.Printf("\033[32m[OK]\033[0m Log file cleared: %s\n", logFile)
			}
		}
		return
	}

	if base == "" || target == "" {
		fmt.Println("Error: Both base (-b) and target (-t) directories must be specified")
		help()
		return
	}

	verify(base, target, ignoreHashFile, ignorePermFile)
}
