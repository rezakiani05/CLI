import re
from collections import Counter
from datetime import datetime
from dataclasses import dataclass
import plotext as plt
import gzip
import time
import argparse
import json

class LogAnalyzer:
    def __init__(self):
        self.total_lines = 0
        self.malformed_lines = 0
        self.unique_ips = set()
        self.endpoints = Counter()
        self.status_groups = Counter({"4xx": 0, "5xx": 0, "other": 0})
        self.hourly_distribution = Counter()
        self.sus_users = Counter()
        self.hourly_errors_5xx = Counter()

    def add_line(self):
        self.total_lines += 1

    def add_malformed_line(self):
        self.malformed_lines += 1

    def add_ip(self, ip: str):
        self.unique_ips.add(ip)

    def add_endpoints(self, path: str):
        self.endpoints[path] += 1

    def add_status(self, status: int):
        if 400 <= status < 500:
            self.status_groups["4xx"] += 1
        elif 500 <= status < 600:
            self.status_groups["5xx"] += 1
        else:
            self.status_groups["other"] += 1

    def add_hourly_traffic(self, hour: int):
        self.hourly_distribution[hour] += 1

    def add_sus_users(self, ip: str):
        self.sus_users[ip] += 1

    def add_hourly_errors_5xx(self, hour: int):
        self.hourly_errors_5xx[hour] += 1
@dataclass
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    size: int
    user_agent: str

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

def parse_line(line):
    match = LOG_PATTERN.match(line)
    if match is None:
        raise LogParseError(f"خط با فرمت مطابقت نداره: {line!r}")

    groups = match.groupdict()

    try:
        status = int(groups["status"])
    except ValueError:
        raise LogParseError(f"status نامعتبر: {groups['status']!r}")

    raw_size = groups["size"]
    if raw_size == "-":
        size = 0
    else:
        try:
            size = int(raw_size)
        except ValueError:
            raise LogParseError(f"size نامعتبر: {raw_size!r}")

    try:
        timestamp = datetime.strptime(groups["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        raise LogParseError(f"timestamp نامعتبر: {groups['timestamp']!r}")

    return LogEntry(
        ip=groups["ip"],
        timestamp=timestamp,
        method=groups["method"],
        path=groups["path"],
        protocol=groups["protocol"],
        status=status,
        size=size,
        user_agent=groups["user_agent"],
    )


class LogParseError(Exception):
    pass


def analyze(entry: LogEntry, analyzer: LogAnalyzer):

    analyzer.add_ip(entry.ip)

    analyzer.add_endpoints(entry.path.strip())

    analyzer.add_status(entry.status)

    analyzer.add_hourly_traffic(entry.timestamp.hour)

    if entry.path.strip("/") == "login" and entry.status == 401:
        analyzer.add_sus_users(entry.ip)

    if 500 <= entry.status < 600:
        analyzer.add_hourly_errors_5xx(entry.timestamp.hour)
    pass


def process_file(path, top_n, export_json):
    start_time = time.time()
    analyzer = LogAnalyzer()

    if path.endswith(".gz"):
        open_func = gzip.open(path, "rt", encoding="utf-8", errors="replace")
    else:
        open_func = open(path, "r", encoding="utf-8", errors="replace")

    with open_func as f:
        for raw_line in f:
            line = raw_line.strip()

            if not line:
                continue

            analyzer.add_line()

            try:
                entry = parse_line(line)
                analyze(entry, analyzer)
            except LogParseError:
                analyzer.add_malformed_line()
                continue



    execution_time = time.time() - start_time

    number_of_errors = analyzer.status_groups["4xx"] + analyzer.status_groups["5xx"]
    total_status = sum(analyzer.status_groups.values())
    percent_of_error = (number_of_errors / total_status) * 100 if total_status > 0 else 0.0

    error_spikes = []
    threshold_of_hourly_traffic = 10.0
    for hour, count in analyzer.hourly_errors_5xx.items():
        total_hour_traffic = analyzer.hourly_distribution[hour]
        if total_hour_traffic > 0:
            percent_hourly_traffic = (count / total_hour_traffic) * 100
            if percent_hourly_traffic >= threshold_of_hourly_traffic:
                error_spikes.append({
                    "hour": hour,
                    "count": count,
                    "rate": f"{percent_hourly_traffic:.2f}%"
                })

    suspicious_ips = {ip: count for ip, count in analyzer.sus_users.items() if count >= 3}

    if export_json:
        report_data = {
            "summary": {
                "total_lines": analyzer.total_lines,
                "malformed_lines": analyzer.malformed_lines,
                "unique_ips_count": len(analyzer.unique_ips),
                "global_error_rate": f"{percent_of_error:.2f}%"
            },
            "top_endpoints": [{"path": path, "requests": count} for path, count in
                              analyzer.endpoints.most_common(top_n)],
            "suspicious_brute_force_ips": suspicious_ips,
            "hourly_error_spikes_5xx": error_spikes,
            "performance": {
                "execution_time_seconds": round(execution_time, 4)
            }
        }
        with open("report.json", "w", encoding="utf-8") as json_file:
            json.dump(report_data, json_file, indent=4, ensure_ascii=False)
        print("✅ Success: System report exported to 'report.json'.")
        return

    print("\n" + "═" * 66)
    print(f" {'LOG ANALYSIS SUMMARY REPORT':^64} ")
    print("═" * 66)
    print(f" 📂 Log Source Path:    {path}")
    print(f" 🔢 Total Lines:         {analyzer.total_lines:,}")
    print(f" ⚠️ Malformed Lines:    {analyzer.malformed_lines:,}")
    print(f" 🌐 Unique IP Addresses: {len(analyzer.unique_ips):,}")
    print(f" 📉 Global Error Rate:   {percent_of_error:.2f}%")
    print("─" * 66)

    print(f"\n 🔥 TOP {top_n} ENDPOINTS:")
    top_endpoints = analyzer.endpoints.most_common(top_n)
    for index, (path_name, count) in enumerate(top_endpoints, 1):
        print(f"   {index:02d}. Path: {path_name:<35} | Requests: {count:,}")
    print("─" * 66)

    print("\n" + "═" * 66)
    print(f" {'VERTICAL HOURLY TRAFFIC HISTOGRAM':^64} ")
    print("═" * 66 + "\n")

    hours = list(range(24))
    counts = [analyzer.hourly_distribution[h] for h in hours]
    max_count = max(counts) if counts else 1
    graph_height = 15

    for level in range(graph_height, 0, -1):
        line_str = ""
        for hour in hours:
            if (counts[hour] / max_count) * graph_height >= level:
                line_str += "  ██ "
            else:
                line_str += "     "
        print(line_str)

    print(" ──" + "─────" * 23 + "── ")
    hour_labels = "".join(f" {h:02d}  " for h in hours)
    print(hour_labels)
    print("\n" + "═" * 66)

    print("\n 🚨 SECURITY ANOMALY DETECTION (401 on /login):")
    if suspicious_ips:
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"   ⚠️ Suspicious IP: {ip:<15} | Failed Attempts: {count}")
    else:
        print("   ✅ No suspicious brute-force activity detected.")
    print("─" * 66)

    print("\n 📉 AUTOMATIC ERROR SPIKE DETECTION (5xx > 10%):")
    if error_spikes:
        for spike in error_spikes:
            print(
                f"   💥 Hour {spike['hour']:02d}:00 | 5xx Errors: {spike['count']:<4} | Failure Rate: {spike['rate']}")
    else:
        print("   ✅ Server health stable. No significant error spikes detected.")
    print("─" * 66)

    print(f"\n ⏱️ Performance Execution Time: {execution_time:.4f} seconds\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional Log Analyzer CLI")

    parser.add_argument("path", type=str, help="Path to the log file (.log or .gz)")

    parser.add_argument("--top", type=int, default=10, help="Number of top endpoints to display")

    parser.add_argument("--json", action="store_true", help="Export output to a JSON file")

    args = parser.parse_args()

    process_file(args.path, args.top, args.json)


