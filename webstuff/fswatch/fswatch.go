package main

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

func fswatch(dir string, regexPattern string) {
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		log.Printf("Invalid regex pattern: %v", err)
		return
	}

	watchDir, err := os.Open(dir)
	if err != nil {
		log.Printf("Failed to open directory: %v", err)
		return
	}
	watchDir.Close()

	fd, err := syscall.InotifyInit()
	if err != nil {
		log.Printf("Failed to initialize inotify: %v", err)
		return
	}
	defer syscall.Close(fd)

	wd, err := syscall.InotifyAddWatch(fd, dir, syscall.IN_CLOSE_WRITE)
	if err != nil {
		log.Printf("Failed to add inotify watch: %v", err)
		return
	}
	defer syscall.InotifyRmWatch(fd, uint32(wd))

	log.Printf("Watching directory: %s for CLOSE_WRITE events..", dir)

	buf := make([]byte, syscall.SizeofInotifyEvent*syscall.Getpagesize())

	for {
		n, err := syscall.Read(fd, buf[:])
		if err != nil {
			log.Printf("Error reading inotify events: %v", err)
			return
		}
		for offset := uint32(0); offset < uint32(n); {

			event := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))

			if event.Len > 0 {
				i := offset + syscall.SizeofInotifyEvent
				filename := strings.TrimRight(string(buf[i:i+event.Len]), "\x00")

				if event.Mask&syscall.IN_CLOSE_WRITE == syscall.IN_CLOSE_WRITE {
					filePath := filepath.Join(dir, filename)
					log.Printf("got '%s':%d @ %v", filename, len(filename), offset)

					if regex.MatchString(filename) {
						log.Printf("File '%s' matched regex '%s'", filePath, regexPattern)
					} else {
						log.Printf("File '%s' did NOT match regex '%s'", filePath, regexPattern)
					}
				}
			}

			offset += syscall.SizeofInotifyEvent + event.Len
		}
	}
}

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <directory> <regex>\n", os.Args[0])
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	dir := os.Args[1]
	regexPattern := os.Args[2]

	var wg sync.WaitGroup

	wg.Add(1)
	defer func() {
		defer wg.Done()
		fswatch(dir, regexPattern)
	}()
	go func() {
		wg.Wait()
	}()
}
