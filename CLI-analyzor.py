import re
import sys
from collections import Counter
from datetime import datetime
from dataclasses import dataclass
import plotext as plt


class LogAnalyzer:
    def __init__(self):
        self.total_lines = 0
        self.malformed_lines = 0
        self.unique_ips = set()
        self.endpoints = Counter()
        self.status_groups = Counter({"4xx": 0, "5xx": 0, "other": 0})
        self.hourly_distribution = Counter()

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
    pass


def process_file(path):
    analyzer = LogAnalyzer()


    with open(path, "r", encoding="utf-8", errors="replace") as f:
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

    print(analyzer.total_lines)
    print(analyzer.malformed_lines)
    print(analyzer.unique_ips.__len__())

    top_10 = analyzer.endpoints.most_common(10)
    for index, (path, count) in enumerate(top_10, 1):
        print(f"{index}. Path: {path:<40} | Requests: {count}")


    number_of_errors = analyzer.status_groups["4xx"] + analyzer.status_groups["5xx"]
    total_status = sum(analyzer.status_groups.values())
    percent_of_error = (number_of_errors / total_status) * 100
    print(percent_of_error)



    print("\n" + "=" * 66)
    print(f"{'VERTICAL HOURLY TRAFFIC HISTOGRAM':^66}")
    print("=" * 66 + "\n")

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
    print("\n" + "=" * 66)


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("❌ Error: Please provide the log file path.")
        print("Usage: python CLI-analyzor.py <path_to_log_file>")
        sys.exit(1)

    path = sys.argv[1]

    process_file(path)


