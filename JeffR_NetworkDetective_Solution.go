package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {

	// argsWithProg := os.Args
	argsWithoutProg := os.Args[1:]

	/*
		arg := os.Args[3]

		fmt.Println(argsWithProg)
		fmt.Println(argsWithoutProg)
		fmt.Println(arg)
	*/

	interactiveMode := false

	if len(argsWithoutProg) == 0 {
		interactiveMode = true
	} else {

	}

	if interactiveMode {
		advertiseHelpFlag()
		// runConsole();
	} else {
		helpPtr := flag.Bool("h", false, "")
		flag.Parse()

		fileSpec := ""
		if *helpPtr {
			emitHelp()
		} else {
			args := flag.Args()
			if len(args) > 0 {
				fileSpec = args[0]
			}

			if len(fileSpec) > 0 {
				if !processLogFile(fileSpec) {
					emitHelp()
				}
			} else {
				emitHelp()
			}
		}

	}

}

func advertiseHelpFlag() {
	fmt.Println("use -? for help with command line")
}

func emitHelp() {
	prog := filepath.Base(os.Args[0])
	fmt.Println("Syntax: ", prog, " [-h|<trafficLogFileName>]")
	fmt.Println("Analyzes a network traffic log and summarizes activity / identifies threats")
}

func processLogFile(fileSpec string) bool {

	fileInfo, err := os.Stat(fileSpec)
	if err != nil {
		log.Println(err) // .Fatal or .Panic aborts processing
		return false
	}

	fmt.Println("Processing " + fileInfo.Name())

	file, err := os.Open(fileSpec)
	if err != nil {
		log.Println(err)
		return false
	}

	reader := bufio.NewReader(file)

	lineNum := 0
	dataLines := 0

	for {
		line, err := reader.ReadString('\n')

		line = strings.TrimSpace(line)

		fmt.Println("processing: ", line)

		if err == io.EOF {
			if len(line) == 0 {
				break
			}
		} else if err != nil {
			log.Println(err)
			return false
		}

		if len(line) > 0 {
			fields := strings.FieldsFunc(line, func(r rune) bool {
				if r == ',' {
					return true
				}
				return false
			})

			if len(fields) != 4 {
				log.Println("Invalid log format at line#", lineNum+1, ":", line)
				return false
			}

			dataLines++
		}

		lineNum++

		if err == io.EOF {
			break
		}

	}

	fmt.Println("Processed", lineNum, "lines of log input with", dataLines, "data points.")

	if lineNum == 0 || dataLines == 0 {
		log.Println("ERR: no traffic found to analyze")
		return false
	}

	return true
}
