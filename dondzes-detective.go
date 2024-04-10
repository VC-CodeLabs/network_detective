package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
//	"strconv"
	"strings"
	"time"
	"math"
)

// LogEvent represents a single log event
type LogEvent struct {
	Timestamp time.Time
	IPAddress string
	Action    string
	Status    string
}

// LogData represents log data grouped by IP address
type LogData map[string][]LogEvent

// ThreatReport represents the threat report
type ThreatReport map[string]map[string]int

// StatusCodesByIP represents status codes and their count by IP address
type StatusCodesByIP map[string]map[string]int

// ParseLogFile parses the log file and extracts network events
func ParseLogFile(filePath string) (LogData, error) {
	logData := make(LogData)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	for {
		row, err := reader.Read()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}

		timestampStr, ipAddress, action, status := row[0], row[1], row[2], row[3]
		timestamp, err := time.Parse("2006-01-02T15:04:05", timestampStr)
		if err != nil {
			return nil, err
		}

		event := LogEvent{
			Timestamp: timestamp,
			IPAddress: ipAddress,
			Action:    action,
			Status:    status,
		}

		logData[ipAddress] = append(logData[ipAddress], event)
	}

	return logData, nil
}

// AnalyzeLog analyzes the log data and generates threat report
func AnalyzeLog(logData LogData) (ThreatReport, StatusCodesByIP) {
	threatReport := make(ThreatReport)
	statusCodesByIP := make(StatusCodesByIP)

	for ip, events := range logData {
		totalRequests := len(events)
		failedLogins := 0
		unusualActivity := false

		for _, event := range events {
			if strings.HasPrefix(event.Action, "POST /login") && event.Status != "200" {
				failedLogins++
			}
			if contains([]string{"401", "403", "404", "500", "503"}, event.Status) {
				unusualActivity = true
			}

			if _, ok := statusCodesByIP[ip]; !ok {
				statusCodesByIP[ip] = make(map[string]int)
			}
			statusCodesByIP[ip][event.Status]++
		}

		threatReport[ip] = map[string]int{
			"Total Requests":       totalRequests,
			"Failed Login Attempts": failedLogins,
			"Unusual Activity":     boolToInt(unusualActivity),
		}
	}

	return threatReport, statusCodesByIP
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GenerateThreatReport generates the HTML threat report
func GenerateThreatReport(threatReport ThreatReport, peakActivity, lowActivity time.Time, statusCodesByIP StatusCodesByIP) {
	fmt.Println("Threat Report:")
	for ip, data := range threatReport {
		fmt.Printf("IP Address: %s\n", ip)
		for key, value := range data {
			fmt.Printf("%s: %d\n", key, value)
		}
		fmt.Println()
	}

	// Generate HTML threat report
	htmlReport := "<html><head><title>Network Log Analysis Report</title></head><body>"

	// Network Activity Section
	htmlReport += "<h1>Network Activity</h1>"
	htmlReport += "<p>Peak Activity: " + peakActivity.Format("2006-01-02 15:04:05") + "</p>"
	htmlReport += "<p>Low Activity: " + lowActivity.Format("2006-01-02 15:04:05") + "</p>"

	// Sort IP addresses
	var sortedIPs []string
	for ip := range threatReport {
		sortedIPs = append(sortedIPs, ip)
	}
	sort.Strings(sortedIPs)

	// Generate table for total requests and failed logins by IP address
	htmlReport += "<h2 style='text-decoration: underline;'><a href='#' onclick='toggleTable(\"all_activity\")' style='cursor: pointer;'>All Activity</a></h2>"
	htmlReport += "<div id='all_activity' style='display: none;'>"
	htmlReport += "<table border='1'><tr><th>IP Address</th><th>Total Requests</th><th>Failed Login Attempts</th></tr>"
	for _, ip := range sortedIPs {
		data := threatReport[ip]
		htmlReport += fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%d</td></tr>", ip, data["Total Requests"], data["Failed Login Attempts"])
	}
	htmlReport += "</table>"
	htmlReport += "</div>"

	// Generate table for unusual activity
	htmlReport += "<h2 style='text-decoration: underline;'><a href='#' onclick='toggleTable(\"unusual_activity\")' style='cursor: pointer;'>Unusual Activity</a></h2>"
	htmlReport += "<div id='unusual_activity' style='display: none;'>"
	htmlReport += "<table border='1'><tr><th>IP Address</th><th>Total Requests</th><th>Failed Login Attempts</th><th>Status Code Counts</th></tr>"
	for _, ip := range sortedIPs {
		data := threatReport[ip]
		if data["Unusual Activity"] == 1 {
			statusCodes := statusCodesByIP[ip]
			statusCodesString := ""
			for code, count := range statusCodes {
				statusCodesString += fmt.Sprintf("%s: %d, ", code, count)
			}
			statusCodesString = strings.TrimSuffix(statusCodesString, ", ")
			htmlReport += fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td></tr>", ip, data["Total Requests"], data["Failed Login Attempts"], statusCodesString)
		}
	}
	htmlReport += "</table>"
	htmlReport += "</div>"

	htmlReport += "</body></html>"

	// JavaScript function to toggle table visibility
	htmlReport += "<script>"
	htmlReport += "function toggleTable(id) {"
	htmlReport += "var x = document.getElementById(id);"
	htmlReport += "if (x.style.display === 'none') {"
	htmlReport += "x.style.display = 'block';"
	htmlReport += "} else {"
	htmlReport += "x.style.display = 'none';"
	htmlReport += "}"
	htmlReport += "}"
	htmlReport += "</script>"

	// Write HTML report to file
	htmlFileName := "threat_report.html"
	htmlFile, err := os.Create(htmlFileName)
	if err != nil {
		fmt.Println("Error creating HTML file:", err)
		return
	}
	defer htmlFile.Close()

	_, err = htmlFile.WriteString(htmlReport)
	if err != nil {
		fmt.Println("Error writing to HTML file:", err)
		return
	}

	fmt.Println("See HTML report generated:", htmlFileName)
}

// FindPeakAndLowActivityTimestamps finds the peak and low activity timestamps
func FindPeakAndLowActivityTimestamps(logData LogData) (time.Time, time.Time) {
	activityCounts := make(map[time.Time]int)
	for _, events := range logData {
		for _, event := range events {
			activityCounts[event.Timestamp]++
		}
	}

	var peakActivity, lowActivity time.Time
	maxCount := 0
	minCount := math.MaxInt32

	for timestamp, count := range activityCounts {
		if count > maxCount {
			maxCount = count
			peakActivity = timestamp
		} else if count == maxCount && timestamp.Before(peakActivity) {
			maxCount = count
			peakActivity = timestamp
		}
		if count < minCount {
			minCount = count
			lowActivity = timestamp
		} else if count == minCount && timestamp.Before(lowActivity) {
			minCount = count
			lowActivity = timestamp
		}

	}

	return peakActivity, lowActivity
}

func main() {
	filePath := "network_log.txt"
	logData, err := ParseLogFile(filePath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	threatReport, statusCodesByIP := AnalyzeLog(logData)

	// Find peak and low activity timestamps
	peakActivity, lowActivity := FindPeakAndLowActivityTimestamps(logData)

	// generate HTML threat report
	GenerateThreatReport(threatReport, peakActivity, lowActivity, statusCodesByIP)
}
