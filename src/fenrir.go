package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	ignoreAllHashes = false
	ignoreAllPermissions = false
)

func c(str string, opt int) string {
	colors := map[int]string{
		0: "\033[31m",    // RED
		1: "\033[32m",    // GREEN
		2: "\033[33m",    // YELLOW
		3: "\033[0;36m",  // CYAN
	}
	reset := "\033[0m"
	if color, ok := colors[opt]; ok {
		return color + str + reset
	}
	return str
}

func logStatus(symbol string, color int, msg string) { fmt.Printf("%s %s\n", c(symbol, color), msg) }
func fail(msg string)    { logStatus("[-]", 0, msg) }
func alert(msg string)   { logStatus("[!]", 0, msg) }
func success(msg string) { logStatus("[+]", 1, msg) }
func info(msg string)    { logStatus("[#]", 2, msg) }

func reset_logging() {
	logFiles := []string{"conflicts.log", "permission_conflicts.log", "target_specific.log", "base_specific.log"}
	for _, logFile := range logFiles {
		err := os.Remove(logFile)
		if err != nil && !os.IsNotExist(err) {
			fail(fmt.Sprintf("Error clearing log file %s: %s", logFile, err))
		} else {
			success(fmt.Sprintf("Log file cleared: %s", logFile))
		}
	}
	return
}

func checksum(filePath string) string {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		fail(fmt.Sprintf("Error converting to absolute path (%s): %s", c(filePath, 3), err))
		return ""
	}

	info, err := os.Stat(absPath)
	if err != nil {
		fail(fmt.Sprintf("Error accessing file info (%s): %s", c(absPath, 3), err))
		return ""
	}

	if info.IsDir() {
		return ""
	}

	file, err := os.Open(absPath)
	if err != nil {
		fail(fmt.Sprintf("Error reading file (%s): %s", c(absPath, 3), err))
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		fail(fmt.Sprintf("Error calculating SHA-256 hash (%s): %s", c(absPath, 3), err))
		return ""
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func get_permissions(filePath string) int32 {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		fail(fmt.Sprintf("Error converting to absolute path (%s): %s", c(filePath, 3), err))
		return 0
	}
	file, err := os.Open(absPath)
	if err != nil {
		fail(fmt.Sprintf("Error reading file (%s): %s", c(absPath, 3), err))
		return 0
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fail(fmt.Sprintf("Error retrieving file info (%s): %s", c(absPath, 3), err))
		return 0
	}

	return int32(fileInfo.Mode().Perm())
}

func append_log(filename string, text string) error {
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

func load_exclusions(filename string, signal int) (map[string]bool, error) {
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
			fail(fmt.Sprintf("Error converting to absolute path: %s", err))
			continue
		}
		if signal == 0 {
			info(fmt.Sprintf("Hash exclusion loaded (%s)", c(absPath, 3)))
		} else if signal == 1 {
			info(fmt.Sprintf("Permission exclusion loaded (%s)", c(absPath, 3)))
		}
		exclusions[absPath] = true
	}
	return exclusions, nil
}

func verify(base string, target string, ignoreHashFile, ignorePermFile string) {
	ignoreHashes := make(map[string]bool)
	ignorePerms := make(map[string]bool)

	if ignoreHashFile != "" {
		var err error
		ignoreHashes, err = load_exclusions(ignoreHashFile, 0)
		if err != nil {
			fail(fmt.Sprintf("Error loading hash exclusion file: %s", err))
			return
		}
	}
	if ignorePermFile != "" {
		var err error
		ignorePerms, err = load_exclusions(ignorePermFile, 1)
		if err != nil {
			fail(fmt.Sprintf("Error loading permission exclusion file: %s", err))
			return
		}
	}

	baseFiles := make(map[string]struct {
		checksum    string
		permissions int32
	})

	baseAbs, err := filepath.Abs(base)
	if err != nil {
		fail(fmt.Sprintf("Error converting base path to absolute: %s", err))
		return
	}

	targetAbs, err := filepath.Abs(target)
	if err != nil {
		fail(fmt.Sprintf("Error converting target path to absolute: %s", err))
		return
	}

	filepath.WalkDir(baseAbs, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			fail(fmt.Sprintf("Error accessing path (%s): %s", c(path, 3), err))
			return err
		}

		if !entry.IsDir() {
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

	filepath.WalkDir(targetAbs, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			fail(fmt.Sprintf("Error accessing path (%s): %s", c(path, 3), err))
			return err
		}

		if !entry.IsDir() {
			absPath, _ := filepath.Abs(path)
			relativePath, _ := filepath.Rel(targetAbs, absPath)

			if ignoreHashes[absPath] {
				info(fmt.Sprintf("Skipping hash check for excluded file (%s)", c(absPath, 3)))
				return nil
			}

			targetChecksum := checksum(absPath)
			targetPermissions := get_permissions(absPath)

			if baseFile, found := baseFiles[relativePath]; found {
				if !ignoreAllHashes {
					if baseFile.checksum == targetChecksum {
						success(fmt.Sprintf("File matched (%s -> %s)", c(baseAbs+"/"+relativePath, 3), c(targetAbs+"/"+relativePath, 3)))
					} else {
						alert(fmt.Sprintf("Checksum conflict (%s -> %s)", c(baseAbs+"/"+relativePath, 3), c(targetAbs+"/"+relativePath, 3)))
						append_log("conflicts.log", baseAbs+"/"+relativePath+":"+targetAbs+"/"+relativePath+"\n")
					}
				}
				
				if !ignoreAllPermissions {
					if ignorePerms[absPath] {
						info(fmt.Sprintf("Skipping permission check for excluded file (%s)", c(absPath, 3)))
					} else if baseFile.permissions != targetPermissions {
						alert(fmt.Sprintf("Permission conflict (%s): (base: %s, target: %s)", c(targetAbs+"/"+relativePath, 3), fmt.Sprintf("%o", baseFile.permissions), fmt.Sprintf("%o", targetPermissions)))
						append_log("permission_conflicts.log", baseAbs+"/"+relativePath+":"+targetAbs+"/"+relativePath+"\n")
					} else {
						success(fmt.Sprintf("Permissions matched (%s -> %s)", c(baseAbs+"/"+relativePath, 3), c(targetAbs+"/"+relativePath, 3)))
					}
				}
			} else {
				alert(fmt.Sprintf("File exists in target but not in base (%s)", c(targetAbs+"/"+relativePath, 3)))
				append_log("target_specific.log", targetAbs+"/"+relativePath+"\n")
			}
		}
		return nil
	})

	for relativePath := range baseFiles {
		targetPath := filepath.Join(targetAbs, relativePath)
		if _, err := os.Stat(targetPath); os.IsNotExist(err) && !ignoreHashes[targetPath] {
			alert(fmt.Sprintf("File exists in base but not in target (%s/%s)", c(baseAbs, 3), c(relativePath, 3)))
			append_log("base_specific.log", baseAbs+"/"+relativePath+"\n")
		}
	}
}

func help() {
	fmt.Printf("Usage: ./fenrir [OPTION1] [ARGUMENT1] ... [OPTIONn] [ARGUMENTn]\n")
	fmt.Printf("\nOptions:\n")
	fmt.Printf("  -b   Declares base directory (REQUIRES TARGET)\n")
	fmt.Printf("  -t   Declares target directory (REQUIRES BASE)\n")
	fmt.Printf("  -nh  Ignore all hash comparison results\n")
	fmt.Printf("  -np  Ignore all permission comparison results\n")
	fmt.Printf("  -xh  Exclude a file for hash comparison\n")
	fmt.Printf("  -xp  Exclude a file for permission comparison\n")
	fmt.Printf("  -c   Clears all log files\n")
}

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
		case "-nh":
			ignoreAllHashes = true
		case "-np":
			ignoreAllPermissions = true
		default:
			fmt.Printf("Unknown option: %s\n", os.Args[i])
			help()
			return
		}
	}

	if clearLogs {
		reset_logging()
	}

	if base == "" || target == "" {
		fail("Error: Both base (-b) and target (-t) directories must be specified")
		help()
		return
	}

	reset_logging()
	verify(base, target, ignoreHashFile, ignorePermFile)
}