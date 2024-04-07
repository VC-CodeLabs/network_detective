package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
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
				log.Println("ERR: Invalid log format at line#", lineNum+1, ":", line)
				log.Println("ERR: log line format s/b `<timestamp>,<ip>,<method> <path>,<status>`")
				return false
			}

			parsedTime, err := time.Parse("2006-01-02T15:04:05", fields[0])

			if err != nil {
				log.Println("ERR:", err)
				log.Println("ERR: Invalid timestamp at line#", lineNum+1, ":", fields[0])
				log.Println("ERR: timestamp format s/b `<yyyy-mm-ddThh24:mm:ss>`")
				return false
			}

			parsedIP := strings.TrimSpace(fields[1])

			parsedMethodPath := strings.Fields(strings.TrimSpace(fields[2]))

			if len(parsedMethodPath) != 2 {
				log.Println("ERR: Invalid method+path at line#", lineNum+1, ":", fields[2])
				log.Println("ERR: method+path format s/b `<(GET|PUT|POST|DELETE...)><space(s)><path>`")
				return false
			}

			parsedMethod := strings.ToUpper(parsedMethodPath[0])
			parsedPath := parsedMethodPath[1]

			parsedStatus, err := strconv.Atoi(fields[3])

			if err != nil {
				log.Println("ERR: Invalid response status at line#", lineNum+1, ":", fields[3])
				log.Println("ERR: response status format s/b `<100..599>`")
				return false

			}

			// TODO consider valiating / normalizing other inputs

			storeData(parsedTime, parsedIP, parsedMethod, parsedPath, parsedStatus)

			fmt.Println("Processed", parsedTime, parsedIP, parsedMethod, parsedPath, parsedStatus)

			dataLines++
		}

		lineNum++

		if err == io.EOF {
			break
		}

	}

	fmt.Print("Processed ", lineNum, " lines of log input")

	if dataLines != lineNum {
		fmt.Print(" with ", dataLines, " data points.")
	}

	fmt.Println()

	if lineNum == 0 || dataLines == 0 {
		log.Println("ERR: no traffic found to analyze")
		return false
	}

	analyze()
	report()

	return true
}

type networkDataItem struct {
	timestamp  time.Time
	ipAddr     string
	method     string // GET, POST, PUT, DELETE &c
	path       string
	statusCode int // http response code 100-599
}

var networkData []networkDataItem
var byIP map[string][]int = make(map[string][]int)
var requestsByIP map[string]int = make(map[string]int)
var failedLoginsByIP map[string]int = make(map[string]int)
var minTime time.Time
var maxTime time.Time

type trafficVolumeKey struct {
	weekday   time.Weekday
	timeOfDay time.Duration
}

var trafficVolume map[trafficVolumeKey]int = make(map[trafficVolumeKey]int)

func storeData(timestamp time.Time, ipAddr string, method string, path string, statusCode int) {
	if len(networkData) == 0 {
		minTime = timestamp
		maxTime = timestamp
	} else {
		if timestamp.Before(minTime) {
			minTime = timestamp
		}

		if timestamp.After(maxTime) {
			maxTime = timestamp
		}
	}

	hours, minutes, seconds := timestamp.Round(time.Duration(5 * int(time.Minute))).Clock()
	timeOfDay := time.Duration((hours*int(time.Hour) + minutes*int(time.Minute) + seconds*int(time.Second)))
	// YGBFKM
	// timeOfDay, _ := time.ParseDuration("" + strconv.Itoa(hours) + "h" + strconv.Itoa(minutes) + "m" + strconv.Itoa(seconds) + "s")

	fmt.Printf("timeOfDay: %s\n", timeOfDay)

	trafficVolume[trafficVolumeKey{timestamp.Weekday(), timeOfDay}]++

	networkData = append(networkData, networkDataItem{timestamp, ipAddr, method, path, statusCode})

	newDataIndex := len(networkData) - 1

	indexes, ok := byIP[ipAddr]

	if !ok {
		indexes = make([]int, 0)
		byIP[ipAddr] = indexes
	}

	byIP[ipAddr] = append(indexes, newDataIndex)

	requestsByIP[ipAddr]++

	if path == "/login" && isHttpError(statusCode) {
		failedLoginsByIP[ipAddr]++
	}

}

var totalRequests = 0
var totalFailedLogins = 0

type span struct {
	start   time.Time
	end     time.Time
	elapsed time.Duration
}

var activityGaps []span = make([]span, 0)

func analyze() {
	totalRequests = len(networkData)
	isFailedLogin := func(i networkDataItem) bool { return i.path == "/login" && isHttpError(i.statusCode) }
	totalFailedLogins = Count(networkData, isFailedLogin)

	// by IP analysis was done when storing

	// find the spikes
	// here, we go by Day of week and time of day rounded to 5 minute intervals

	/*
		dataSetSpan := maxTime.Sub(minTime);

		startDay := time.Monday
		endDay := time.Sunday
		wraps := true

		if( dataSetSpan < time.Duration(7*24*int(time.Hour))) {
			startDay = minTime.Weekday()
			endDay = maxTime.Weekday()
			wraps = false
		}
	*/

	// find the gaps in traffic
	// here, we use the actual timestamps for a more precise measure

	timestamps := make([]time.Time, 0)
	for _, item := range networkData {
		timestamps = append(timestamps, item.timestamp)
	}

	slices.SortStableFunc(timestamps, func(a time.Time, b time.Time) int {
		return a.Compare(b)
	})

	const MAX_GAPS = 10
	var last time.Time
	for i, timestamp := range timestamps {
		if i > 0 {
			if timestamp == last {
				continue
			}
			elapsed := timestamp.Sub(last)
			/*
				if elapsed == 0 {
					continue
				}
			*/
			currentGap := span{last, timestamp, elapsed}
			gapCount := len(activityGaps)
			if gapCount > 1 {

				var insertAt int = -1

				if elapsed > activityGaps[gapCount-1].elapsed {
					for j, activityGap := range activityGaps {
						if elapsed > activityGap.elapsed {
							insertAt = j
							break
						}
					}
				}

				if insertAt != -1 {
					activityGaps = append(activityGaps[:insertAt+1], activityGaps[insertAt:]...)
					activityGaps[insertAt] = currentGap
				} else if gapCount <= MAX_GAPS {
					activityGaps = append(activityGaps, currentGap)
				}

				if len(activityGaps) > MAX_GAPS {
					activityGaps = activityGaps[:MAX_GAPS]
				}

			} else {
				activityGaps = append(activityGaps, currentGap)
			}
		}
		last = timestamp
	}

}

func Count[T any](ts []T, pred func(T) bool) int {
	matches := 0
	for _, t := range ts {
		if pred(t) {
			matches++
		}
	}
	return matches
}

func isHttpError(statusCode int) bool {
	return statusCode/100 != 2
}

func report() {
	fmt.Println()
	fmt.Println("========================")
	fmt.Println("Network Traffic Analysis")
	fmt.Println("========================")
	fmt.Println()
	fmt.Println("Data spans", minTime, "to", maxTime)
	fmt.Println("Total Requests:", totalRequests)
	fmt.Println("Total Failed Logins:", totalFailedLogins)

	keys := make([]string, 0, len(byIP))
	for key := range byIP {
		keys = append(keys, key)
	}

	// sort so that we get the most failures at the top, subsorted by most requests
	sort.SliceStable(keys, func(i, j int) bool {
		f1, ok1 := failedLoginsByIP[keys[i]]
		f2, ok2 := failedLoginsByIP[keys[j]]

		if ok1 && ok2 {
			return f1 > f2
		} else if ok1 {
			return true
		} else if ok2 {
			return false
		} else {
			return requestsByIP[keys[i]] > requestsByIP[keys[j]]
		}

	})

	fmt.Println()
	fmt.Println("Activity By IP")
	fmt.Println("==============")
	fmt.Println("IP                     #Requests  #Failed Logins")
	fmt.Println("---------------  --------------- ---------------")
	for _, key := range keys {
		fmt.Printf("%-15s  %15d %15d\n", key, requestsByIP[key], failedLoginsByIP[key])
	}

	fmt.Println()
	fmt.Println("Top Activity Gaps")
	fmt.Println("=================")
	fmt.Println("Start                          End                            Duration")
	fmt.Println("-----------------------------  -----------------------------  --------")
	for _, gap := range activityGaps {
		fmt.Printf("%s  %s  %s\n", gap.start, gap.end, gap.elapsed)
	}

}
