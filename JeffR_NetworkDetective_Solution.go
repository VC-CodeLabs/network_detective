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

const VERBOSE = false

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
		fmt.Println("ERR parameter required")
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
	fmt.Println("use -h for help with command line")
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

		if VERBOSE {
			fmt.Println("processing: ", line)
		}

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

			if VERBOSE {
				fmt.Println("Processed", parsedTime, parsedIP, parsedMethod, parsedPath, parsedStatus)
			}

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

type results struct {
	succeeded int64
	failed    int64
	minTOD    time.Duration
	maxTOD    time.Duration
	weight    int64
}

type trafficDetails struct {
	byPath map[string]map[string]results
	// byMethod map[string]results
	byWeekday map[time.Weekday]results
}

var trafficByIP map[string]trafficDetails = make(map[string]trafficDetails)

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

	// fmt.Printf("timeOfDay: %s\n", timeOfDay)

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

	///////////////////////////////

	_, ok = trafficByIP[ipAddr]

	if !ok {
		trafficByIP[ipAddr] = trafficDetails{make(map[string]map[string]results), make(map[time.Weekday]results)}
	}

	_, ok = trafficByIP[ipAddr].byPath[path]

	if !ok {
		trafficByIP[ipAddr].byPath[path] = make(map[string]results)
	}

	_, ok = trafficByIP[ipAddr].byPath[path][method]

	if !ok {
		trafficByIP[ipAddr].byPath[path][method] = results{0, 0, timeOfDay, timeOfDay, 0}
	}

	resultsVal := trafficByIP[ipAddr].byPath[path][method]
	if isHttpSuccess(statusCode) {
		resultsVal.succeeded++
	} else {
		resultsVal.failed++

	}
	if timeOfDay < resultsVal.minTOD {
		resultsVal.minTOD = timeOfDay
	}
	if timeOfDay > resultsVal.maxTOD {
		resultsVal.maxTOD = timeOfDay
	}
	trafficByIP[ipAddr].byPath[path][method] = resultsVal

	_, ok = trafficByIP[ipAddr].byWeekday[timestamp.Weekday()]

	if !ok {
		trafficByIP[ipAddr].byWeekday[timestamp.Weekday()] = results{0, 0, timeOfDay, timeOfDay, 0}
	}

	resultsVal = trafficByIP[ipAddr].byWeekday[timestamp.Weekday()]
	if isHttpSuccess(statusCode) {
		resultsVal.succeeded++
	} else {
		resultsVal.failed++
	}
	if timeOfDay < resultsVal.minTOD {
		resultsVal.minTOD = timeOfDay
	}
	if timeOfDay > resultsVal.maxTOD {
		resultsVal.maxTOD = timeOfDay
	}
	trafficByIP[ipAddr].byWeekday[timestamp.Weekday()] = resultsVal

}

var totalRequests = 0
var totalFailedLogins = 0

var trafficDays map[trafficVolumeKey]int = make(map[trafficVolumeKey]int)

type spike struct {
	start     trafficVolumeKey
	end       trafficVolumeKey
	spans     time.Duration
	requests  int64
	avgRqs    float64
	singleton bool
}

var activitySpikes []spike = make([]spike, 0)

type cyclicalGap struct {
	start trafficVolumeKey
	end   trafficVolumeKey
	spans time.Duration
}

var activityGapsCyclical []cyclicalGap = make([]cyclicalGap, 0)

type span struct {
	start   time.Time
	end     time.Time
	elapsed time.Duration
}

var activityGapsAbsolute []span = make([]span, 0)

func analyze() {
	totalRequests = len(networkData)
	isFailedLogin := func(i networkDataItem) bool { return i.path == "/login" && isHttpError(i.statusCode) }
	totalFailedLogins = Count(networkData, isFailedLogin)

	// by IP analysis was done when storing

	// find the spikes
	// here, we go by Day of week and time of day rounded to 5 minute intervals

	const MAX_SPIKES = 10

	dataSetSpan := maxTime.Sub(minTime)

	startDay := time.Monday
	endDay := time.Sunday
	wraps := true

	if dataSetSpan < time.Duration(7*24*int(time.Hour)) {
		startDay = minTime.Weekday()
		endDay = maxTime.Weekday()
		wraps = false
	}

	if VERBOSE {
		fmt.Println("startDay:", startDay, "endDay:", endDay, "wraps:", wraps)
	}

	volumeKeys := make([]trafficVolumeKey, 0)
	for volumeKey := range trafficVolume {
		volumeKeys = append(volumeKeys, volumeKey)
	}

	slices.SortStableFunc(volumeKeys, func(a trafficVolumeKey, b trafficVolumeKey) int {

		if a.weekday == b.weekday {
			if a.timeOfDay == b.timeOfDay {
				return 0
			} else if a.timeOfDay < b.timeOfDay {
				return -1
			} else {
				return 1
			}
		}

		adjustedWeekdayA := a.weekday - startDay
		if int(adjustedWeekdayA) < 0 {
			adjustedWeekdayA += 7
		}
		adjustedWeekdayB := b.weekday - startDay
		if int(adjustedWeekdayB) < 0 {
			adjustedWeekdayB += 7
		}

		if adjustedWeekdayA < adjustedWeekdayB {
			return -1
		} else {
			return 1
		}

	})

	if VERBOSE {
		fmt.Println()
		fmt.Println("volumeKeys")

		for _, volumeKey := range volumeKeys {
			fmt.Println(volumeKey.weekday, volumeKey.timeOfDay)

		}
	}

	timestamps := make([]time.Time, 0)
	for _, item := range networkData {
		timestamps = append(timestamps, item.timestamp)
	}

	slices.SortStableFunc(timestamps, func(a time.Time, b time.Time) int {
		return a.Compare(b)
	})

	var prevTimestamp time.Time
	for i, timestamp := range timestamps {
		inc := false

		hours, minutes, seconds := timestamp.Round(time.Duration(5 * int(time.Minute))).Clock()
		timeOfDay := time.Duration((hours*int(time.Hour) + minutes*int(time.Minute) + seconds*int(time.Second)))

		if i > 0 {
			if !(prevTimestamp.Year() == timestamp.Year() && prevTimestamp.YearDay() == timestamp.YearDay()) {
				// !sameDay(prevTimestamp,timestamp) {
				inc = true
			} else {
				hours, minutes, seconds := prevTimestamp.Round(time.Duration(5 * int(time.Minute))).Clock()
				prevTimeOfDay := time.Duration((hours*int(time.Hour) + minutes*int(time.Minute) + seconds*int(time.Second)))
				if timeOfDay != prevTimeOfDay {
					inc = true
				}
			}
		} else {
			inc = true
		}

		if inc {
			trafficDays[trafficVolumeKey{timestamp.Weekday(), timeOfDay}]++
		}
		prevTimestamp = timestamp
	}

	for i := 0; i < len(volumeKeys); i++ {
		for j := i; j < len(volumeKeys); j++ {
			startSpike := volumeKeys[i]
			endSpike := volumeKeys[j]
			if i == j {
				if j < len(volumeKeys)-1 {
					nextSpike := volumeKeys[j+1]

					if nextSpike.weekday == startSpike.weekday && int(nextSpike.timeOfDay-startSpike.timeOfDay) == int(5*time.Minute) {
						continue
					}

					if int(nextSpike.weekday) == (int(startSpike.weekday)+1)%7 && toClock(nextSpike.timeOfDay) == "00:00:00" && toClock(startSpike.timeOfDay) == "23:55:00" {
						continue
					}
				}

				endSpike.timeOfDay = time.Duration(int(endSpike.timeOfDay.Seconds())*int(time.Second) + int(5*time.Minute) - int(1*time.Second))
			}
			var spikeRequests int64 = 0
			var trafficDayCount int64 = 0
			for k := i; k <= j; k++ {
				spikeRequests += int64(trafficVolume[volumeKeys[k]])
				if k == i || volumeKeys[k] != volumeKeys[k-1] {
					trafficDayCount = max(trafficDayCount, int64(trafficDays[volumeKeys[k]]))
				}
			}
			spikeDuration := 0
			if startSpike.weekday == endSpike.weekday {
				spikeDuration = int(endSpike.timeOfDay) - int(startSpike.timeOfDay)
			} else {
				spikeDuration = int(endSpike.timeOfDay) - int(startSpike.timeOfDay)
				days := int(endSpike.weekday) - int(startSpike.weekday)
				if days < 0 {
					days += 7
				}
				spikeDuration += days * 24 * int(time.Hour)
			}
			spikeDuration /= int(time.Second)
			if i == j {
				spikeDuration++
			} else {
				spikeDuration += 5 * 60
			}
			// fmt.Println("spikeDuration:", spikeDuration)
			spikeAverage := float64(spikeRequests) / float64(spikeDuration) / float64(trafficDayCount)

			if VERBOSE {
				fmt.Printf("spike- %s %s %d %d %d %f\n", toClock(startSpike.timeOfDay), toClock(endSpike.timeOfDay), spikeDuration, spikeRequests, trafficDayCount, spikeAverage)
			}

			currentSpike := spike{startSpike, endSpike,
				time.Duration(spikeDuration * int(time.Second)), spikeRequests, spikeAverage, i == j}
			spikeCount := len(activitySpikes)

			if spikeCount > 0 {
				var insertAt int = -1

				if spikeAverage >= activitySpikes[spikeCount-1].avgRqs {
					for _i, activitySpike := range activitySpikes {
						if spikeAverage > activitySpike.avgRqs {
							insertAt = _i
							break
						} else if spikeAverage == activitySpike.avgRqs {
							if spikeRequests > activitySpike.requests {
								insertAt = _i
								break
							}
						}
					}
				}

				/*
					if spikeRequests == 2 && trafficDayCount == 2 {
						fmt.Printf("spike insert- %s %s @ %d\n", startSpike.weekday, toClock(startSpike.timeOfDay), insertAt)
					}
				*/

				if insertAt != -1 {
					activitySpikes = append(activitySpikes[:insertAt+1], activitySpikes[insertAt:]...)
					activitySpikes[insertAt] = currentSpike
				} else if spikeCount < MAX_SPIKES {
					activitySpikes = append(activitySpikes, currentSpike)
				}

				if len(activitySpikes) > MAX_SPIKES {
					activitySpikes = activitySpikes[:MAX_SPIKES]
				}

			} else {
				activitySpikes = append(activitySpikes, currentSpike)
			}
		}
	}

	// find the cyclical gaps in traffic
	// here, we use the data "normalized" to weekday and rounded to 5m intervals
	const MAX_GAPS = 10

	var prev trafficVolumeKey
	for i, curr := range volumeKeys {
		if i > 0 {
			cycleStart := prev
			cycleEnd := curr
			// isGap := false
			days := 0

			if prev.weekday != curr.weekday {
				days = int(curr.weekday) - int(prev.weekday)
				if days < 0 {
					days += 7
				}
			}

			dummyPrev, _ := time.Parse("2006-01-02T15:04:05", fmt.Sprintf("2006-01-02T%s", toClock(prev.timeOfDay)))
			dummyCurr, _ := time.Parse("2006-01-02T15:04:05", fmt.Sprintf("2006-01-02T%s", toClock(curr.timeOfDay)))
			dummyCurr = dummyCurr.Add(time.Duration(days * 24 * int(time.Hour)))

			if dummyCurr.Sub(dummyPrev) > time.Duration(5*int(time.Minute)) {
				if VERBOSE {
					fmt.Println("cyclicalGap- processing", toClock(cycleStart.timeOfDay), toClock(cycleEnd.timeOfDay))
				}
				// account for crossing midnight boundary in either direction
				prevDayWas := dummyPrev.Day()
				dummyPrev = dummyPrev.Add(time.Duration(5 * int(time.Minute)))
				if dummyPrev.Day() > prevDayWas {
					if cycleStart.weekday == time.Saturday {
						cycleStart.weekday = time.Sunday
					} else {
						cycleStart.weekday++
					}
				}
				currDayWas := dummyCurr.Day()
				dummyCurr = dummyCurr.Add(time.Duration(-1 * int(time.Second)))
				if dummyCurr.Day() < currDayWas {
					if cycleEnd.weekday == time.Sunday {
						cycleEnd.weekday = time.Saturday
					} else {
						cycleEnd.weekday--
					}
				}

				spans := dummyCurr.Sub(dummyPrev)

				hours, minutes, seconds := dummyPrev.Clock()
				cycleStart.timeOfDay = time.Duration((hours*int(time.Hour) + minutes*int(time.Minute) + seconds*int(time.Second)))

				hours, minutes, seconds = dummyCurr.Clock()
				cycleEnd.timeOfDay = time.Duration((hours*int(time.Hour) + minutes*int(time.Minute) + seconds*int(time.Second)))

				if VERBOSE {
					fmt.Println("cyclicalGap- adjusted", toClock(cycleStart.timeOfDay), toClock(cycleEnd.timeOfDay))
				}

				/*
					cycleStart.timeOfDay = time.Duration(int(cycleStart.timeOfDay) + 5*int(time.Minute))
					cycleEnd.timeOfDay = time.Duration(int(cycleEnd.timeOfDay) - 1*int(time.Second))
				*/
				newGap := cyclicalGap{cycleStart, cycleEnd, spans}
				cycleCount := len(activityGapsCyclical)

				if cycleCount > 0 {
					insertAt := -1
					if newGap.spans > activityGapsCyclical[cycleCount-1].spans {
						for c, cycle := range activityGapsCyclical {
							if newGap.spans > cycle.spans {
								insertAt = c
								break
							}
						}

					}

					if insertAt != -1 {
						activityGapsCyclical = append(activityGapsCyclical[:insertAt+1], activityGapsCyclical[insertAt:]...)
						activityGapsCyclical[insertAt] = newGap

					} else if cycleCount < MAX_GAPS {
						activityGapsCyclical = append(activityGapsCyclical, newGap)
					}

					if len(activityGapsCyclical) > MAX_GAPS {
						activityGapsCyclical = activityGapsCyclical[:MAX_GAPS]
					}

				} else {
					activityGapsCyclical = append(activityGapsCyclical, newGap)
				}
			} else {
				if VERBOSE {
					fmt.Println("cyclicalGap- skipping", toClock(cycleStart.timeOfDay), toClock(cycleEnd.timeOfDay))
				}
			}
		}
		prev = curr
	}

	// find the absolute gaps in traffic
	// here, we use the actual timestamps for a more precise measure

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
			gapCount := len(activityGapsAbsolute)
			if gapCount > 0 {

				var insertAt int = -1

				if elapsed > activityGapsAbsolute[gapCount-1].elapsed {
					for j, activityGap := range activityGapsAbsolute {
						if elapsed > activityGap.elapsed {
							insertAt = j
							break
						}
					}
				}

				if insertAt != -1 {
					activityGapsAbsolute = append(activityGapsAbsolute[:insertAt+1], activityGapsAbsolute[insertAt:]...)
					activityGapsAbsolute[insertAt] = currentGap
				} else if gapCount <= MAX_GAPS {
					activityGapsAbsolute = append(activityGapsAbsolute, currentGap)
				}

				if len(activityGapsAbsolute) > MAX_GAPS {
					activityGapsAbsolute = activityGapsAbsolute[:MAX_GAPS]
				}

			} else {
				activityGapsAbsolute = append(activityGapsAbsolute, currentGap)
			}
		}
		last = timestamp
	}

	weightTrafficByIP()

}

func weightTrafficByIP() {

	ipAddrs := make([]string, 0)
	for ipAddr := range trafficByIP {
		ipAddrs = append(ipAddrs, ipAddr)

	}

	for _, ipAddr := range ipAddrs {
		ipDetails := trafficByIP[ipAddr]

		for _, otherIpAddr := range ipAddrs {
			if otherIpAddr != ipAddr {
				otherIpDetails := trafficByIP[otherIpAddr]

				for path := range ipDetails.byPath {

					for method := range ipDetails.byPath[path] {
						results := ipDetails.byPath[path][method]
						otherResults, ok := otherIpDetails.byPath[path][method]

						if ok {
							updated := false
							// fmt.Printf("CHECK WEIGHT: %s %s %s %s\n", ipAddr, path, method, otherIpAddr)
							if results.succeeded > 0 && otherResults.succeeded > 0 {
								results.weight += otherResults.succeeded
								updated = true
							}

							if results.failed > 0 {
								results.weight += -results.failed
								updated = true
							}

							if updated {
								ipDetails.byPath[path][method] = results
								// fmt.Printf("WEIGHT: %s %s %s %d\n", ipAddr, path, method, results.weight)
							}

						}

					}
				}

			}
		}

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

func isHttpSuccess(statusCode int) bool {
	return !isHttpError(statusCode)
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
	fmt.Println("Top Activity Spikes**")
	fmt.Println("=====================")
	fmt.Println("Start (+/-2.5m)      End  (+/-2.5m)           ~Spans        #Rqs        Days  Rq/S/Day")
	fmt.Println("-------------------  -------------------  ----------  ----------  ----------  ----------")
	for _, spike := range activitySpikes {
		if spike.singleton {
			fmt.Printf("%9s  %8s  %9s  %8s  %10s  %10d  %10d  %10f\n",
				spike.start.weekday, toClock(spike.start.timeOfDay),
				"", "*",
				"(5m)", spike.requests, trafficDays[spike.start], spike.avgRqs)

		} else {
			fmt.Printf("%9s  %8s  %9s  %8s  %10s  %10d  %10d  %10f\n",
				spike.start.weekday, toClock(spike.start.timeOfDay),
				spike.end.weekday, toClock(spike.end.timeOfDay),
				spike.spans, spike.requests, trafficDays[spike.start], spike.avgRqs)
		}
	}
	fmt.Println("** data timestamps rounded to 5 minute intervals")

	fmt.Println()
	fmt.Println("Top Cyclical Activity Gaps**")
	fmt.Println("============================")
	fmt.Println("Start                                End       Spans")
	fmt.Println("-------------------  -------------------  ----------")
	for _, cyclical := range activityGapsCyclical {
		fmt.Printf("%9s  %8s  %9s  %8s  %10s\n", cyclical.start.weekday, toClock(cyclical.start.timeOfDay),
			cyclical.end.weekday, toClock(cyclical.end.timeOfDay),
			cyclical.spans)
	}
	fmt.Println("** data timestamps rounded to 5 minute intervals")
	fmt.Println("** longer-duration logs (minimum > 1 week) produce more predictive long-term cyclical gaps")

	fmt.Println()
	fmt.Println("Top Absolute Activity Gaps")
	fmt.Println("==========================")
	fmt.Println("Start                          End                            Duration")
	fmt.Println("-----------------------------  -----------------------------  --------")
	for _, gap := range activityGapsAbsolute {
		fmt.Printf("%s  %s  %s\n", gap.start, gap.end, gap.elapsed)
	}

	reportTrafficByIP()

}

func reportTrafficByIP() {
	fmt.Println()
	fmt.Println("Traffic By IP")
	fmt.Println("=============")
	fmt.Println("Sorted by overall Failure \"Density\" (Worst-to-Best)")
	fmt.Println("#Succeeded/#Requests by Day of Week")
	fmt.Printf("%15s", "")
	dayNames := []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
	for _, dayName := range dayNames {
		fmt.Printf("  %15s", dayName)
	}
	fmt.Println()

	ipAddrs := make([]string, 0)
	for ipAddr := range trafficByIP {
		ipAddrs = append(ipAddrs, ipAddr)
	}

	slices.SortStableFunc(ipAddrs, func(a string, b string) int {
		var aFailed int64 = 0
		var aSucceeded int64 = 0
		for _, weekdayResults := range trafficByIP[a].byWeekday {
			aFailed += weekdayResults.failed
			aSucceeded += weekdayResults.succeeded

		}
		var bFailed int64 = 0
		var bSucceeded int64 = 0
		for _, weekdayResults := range trafficByIP[b].byWeekday {
			bFailed += weekdayResults.failed
			bSucceeded += weekdayResults.succeeded

		}

		// list more failures first
		if aFailed < bFailed {
			return 1
		} else if aFailed > bFailed {
			return -1
		}

		// list fewer successes first
		if aSucceeded < bSucceeded {
			return -1
		} else if aSucceeded > bSucceeded {
			return 1
		}

		return strings.Compare(a, b)
	})

	weekdays := []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday, time.Sunday}
	for _, ipAddr := range ipAddrs {
		fmt.Printf("%-15s", ipAddr)
		for _, weekday := range weekdays {
			byWeekday := trafficByIP[ipAddr].byWeekday[weekday]
			stats := fmt.Sprintf("  %d/%d", byWeekday.succeeded, byWeekday.succeeded+byWeekday.failed)
			fmt.Printf("  %15s", stats)
		}
		fmt.Println()
	}

	/////////////////////////

	slices.SortStableFunc(ipAddrs, func(a string, b string) int {
		var aUpWeight int64 = 0
		var aDownWeight int64 = 0
		var aFailed int64 = 0
		var aSucceeded int64 = 0
		for _, pathResults := range trafficByIP[a].byPath {
			for _, methodResults := range pathResults {
				aFailed += methodResults.failed
				aSucceeded += methodResults.succeeded
				if methodResults.weight < 0 {
					aDownWeight += methodResults.weight
				} else {
					aUpWeight += methodResults.weight
				}

			}

		}

		var bUpWeight int64 = 0
		var bDownWeight int64 = 0
		var bFailed int64 = 0
		var bSucceeded int64 = 0
		for _, pathResults := range trafficByIP[b].byPath {
			for _, methodResults := range pathResults {
				bFailed += methodResults.failed
				bSucceeded += methodResults.succeeded
				if methodResults.weight < 0 {
					bDownWeight += methodResults.weight
				} else {
					bUpWeight += methodResults.weight
				}

			}

		}

		// list heavier items first
		if aDownWeight < bDownWeight {
			return -1
		} else if aDownWeight > bDownWeight {
			return 1
		}

		if aUpWeight < bUpWeight {
			return 1
		} else if aUpWeight > bUpWeight {
			return -1
		}

		// list more failures first
		if aFailed < bFailed {
			return 1
		} else if aFailed > bFailed {
			return -1
		}

		// list fewer successes first
		if aSucceeded < bSucceeded {
			return -1
		} else if aSucceeded > bSucceeded {
			return 1
		}

		return strings.Compare(a, b)
	})

	paths := make(map[string]bool)
	for ipAddr := range trafficByIP {
		for path := range trafficByIP[ipAddr].byPath {
			paths[path] = true
		}

	}

	pathNames := make([]string, 0)
	for path := range paths {
		pathNames = append(pathNames, path)
	}

	sort.Strings(pathNames)

	fmt.Println()
	fmt.Println("#Succeeded/#Requests By Path / Method(s)** Weight")
	fmt.Printf("%15s", "")
	for _, path := range pathNames {
		fmt.Printf("  %15s", path)
	}
	fmt.Println()

	for _, ipAddr := range ipAddrs {
		trafficDetail := trafficByIP[ipAddr]
		fmt.Printf("%-15s", ipAddr)
		rqSummary := ""
		mwSummary := ""
		for _, path := range pathNames {
			// fmt.Printf(" %10s", path)
			ipPaths, ok := trafficDetail.byPath[path]
			if ok {
				methods := ""
				var totSuccesses int64 = 0
				var totFailures int64 = 0
				var weight int64 = 0
				for method, results := range ipPaths {
					abbrev := "?"
					if strings.ToUpper(method) == "PUT" || strings.ToUpper(method) == "PATCH" {
						abbrev = strings.ToUpper(method[1:2])
					} else {
						abbrev = strings.ToUpper(method[0:1])
					}
					methods += abbrev

					weight += results.weight
					totSuccesses += results.succeeded
					totFailures += results.failed
				}
				mwSummary += fmt.Sprintf("  %9s %5d", methods, weight)
				stats := fmt.Sprintf("  %d/%d", totSuccesses, totSuccesses+totFailures)
				rqSummary += fmt.Sprintf("  %15s", stats)
			} else {
				mwSummary += fmt.Sprintf("  %15s", "")
				rqSummary += fmt.Sprintf("  %15s", "x")
			}

		}

		fmt.Println(rqSummary)
		fmt.Printf("%15s%s\n", "", mwSummary)

	}
	fmt.Println("**Methods: G=GET, POST=P, DELETE=D, U=PUT, A=PATCH, H=HEAD, C=CONNECT, O=OPTIONS, T=TRACE")

}

func toClock(v time.Duration) string {
	_v := int(v.Seconds())
	s := _v % 60
	_v /= 60
	m := _v % 60
	_v /= 60
	h := _v

	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
