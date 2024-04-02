# Network Detective

**Objective**</br>
You are to develop the Advanced Network Log Analyzer, a tool that sifts through more extensive logs with precision and unmatched speed.

**Data**</br>
**Input File**: A detailed log file containing an array of network events. Each line records a single event with a timestamp, IP address, request action, and response status.</br>
**Max File Size**: 50MB
**Input File Name**: network_log.txt

*Sample*

```
2023-03-15T08:00:00,192.168.1.1,GET /index.html,200
2023-03-15T08:00:02,192.168.1.2,POST /login,403
2023-03-15T08:00:05,192.168.1.1,GET /dashboard,200
2023-03-15T09:00:00,192.168.1.3,POST /login,200
2023-03-15T09:00:03,192.168.1.2,GET /profile,404
2023-03-15T09:00:06,192.168.1.2,POST /login,403
2023-03-15T09:01:00,192.168.1.1,GET /settings,200
2023-03-15T10:00:00,192.168.1.4,GET /contact,500
2023-03-15T10:00:02,192.168.1.5,POST /api/data,201
2023-03-15T10:00:05,192.168.1.6,DELETE /api/user,403
2023-03-15T10:30:00,192.168.1.2,POST /logout,200
2023-03-15T11:00:00,192.168.1.1,GET /about,304
```

**The Challenge**</br>
Log Parsing: Convert these intricate log entries into a beautiful, well-structured, easily navigable format report.

* Solution must be written in Go
* Total requests and failed login attempts by IP address.
* Detection of unusual activity patterns or potential security breaches.
* Traffic analysis to determine peak and low activity periods.
* Comprehensive Threat Report: Assemble your findings into a detailed threat report, providing actionable insights into the network's security posture and activity trends.

**Winning Criteria**</br>
The title of top network detective will go to the participant whose submission:

* Accurately completes all analysis tasks.
* Creativity with a generated report for analysis (subjective; I'll have a group of people review to help decide the best report)
* Generates the threat report with the fastest execution speed, measured in milliseconds.
