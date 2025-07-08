import re
from datetime import datetime
from pathlib import Path

# 사용자 설정
LOG_DIR = Path("./secure_logs")  # 로그 저장된 디렉터리
IP_FILE = Path("ips.txt")        # 분석 대상 IP 목록
YEAR = 2025                      # 로그에 연도 정보가 없으므로 수동 설정

# 로그의 날짜 형식 추출용 정규식 (예: May 25 03:42:18)
DATE_PATTERN = re.compile(r'([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})')

# 월 이름을 숫자로 변환하기 위한 매핑
MONTHS = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
    'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
    'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
}

def parse_log_time(log_line):
    """로그 한 줄에서 날짜 정보를 파싱하고 표준 형식으로 변환"""
    match = DATE_PATTERN.search(log_line)
    if match:
        mon_str, day, time = match.groups()
        mon = MONTHS.get(mon_str, '01')
        return f"{YEAR}-{mon}-{int(day):02d} {time}"
    return None

def extract_logs_by_ip(log_files, ip):
    """모든 로그 파일에서 해당 IP가 포함된 줄만 추출"""
    matched_lines = []
    for log_file in log_files:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if ip in line:
                    matched_lines.append(line.strip())
    return matched_lines

def main():
    # secure_logs 디렉터리에서 secure* 파일 모두 읽음
    log_files = sorted(LOG_DIR.glob("secure*"))
    if not log_files:
        print("No secure logs found in directory.")
        return

    # IP 목록 파일 확인
    if not IP_FILE.exists():
        print("ips.txt not found.")
        return

    # 출력 헤더 (탭 구분)
    print("IP\tFirst Access\tLast Access")

    # 각 IP에 대해 로그 분석
    with open(IP_FILE, 'r') as f:
        for ip in f:
            ip = ip.strip()
            if not ip:
                continue

            logs = extract_logs_by_ip(log_files, ip)

            if not logs:
                print(f"{ip}\tNo logs found\tNo logs found")
                continue

            first_time = parse_log_time(logs[0])
            last_time = parse_log_time(logs[-1])

            print(f"{ip}\t{first_time}\t{last_time}")

if __name__ == "__main__":
    main()
