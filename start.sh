#!/bin/bash

# --- 설정 구간 ---
CSV_FILE="cloudflare-radar_top-200-domains_20260119-20260126.csv"
BLACKLIST_FILE="dropped.txt"
EXE="./main"
OUTPUT_DIR="./captures"
ITERATIONS=500
CONCURRENCY=10  # 동시 실행 프로세스 수
FAILED_LOG="failed_domains.log"

mkdir -p "$OUTPUT_DIR"

# 1. 유효한 도메인 리스트 생성 (블랙리스트 제외)
VALID_DOMAINS_FILE="valid_domains.tmp"
> "$VALID_DOMAINS_FILE"

declare -A BLACKLIST
if [ -f "$BLACKLIST_FILE" ]; then
    while IFS= read -r line; do
        # 도메인 이름만 추출
        clean_domain=$(echo "$line" | awk '{print $NF}' | xargs)
        [ -n "$clean_domain" ] && BLACKLIST["$clean_domain"]=1
    done < "$BLACKLIST_FILE"
fi

while IFS=, read -r RAW_DOMAIN || [ -n "$RAW_DOMAIN" ]; do
    DOMAIN=$(echo "$RAW_DOMAIN" | tr -d '\r\n"' | xargs)
    if [[ -n "$DOMAIN" && "$DOMAIN" != "domain" && ! ${BLACKLIST["$DOMAIN"]} ]]; then
        echo "$DOMAIN" >> "$VALID_DOMAINS_FILE"
    fi
done < "$CSV_FILE"

# 2. 캡처 실행 함수 정의 (xargs에서 호출)
do_capture() {
    DOMAIN=$1
    ROUND=$2
    SAFE_DOMAIN=$(echo "$DOMAIN" | tr '.' '_')
    TIMESTAMP=$(date +"%H%M%S_%N") # 나노초 단위 포함
    
    FILENAME="${SAFE_DOMAIN}_R${ROUND}_${TIMESTAMP}.pcap"
    
    # Go 실행 (URL과 고유 파일명을 인자로 전달)
    timeout -s 9 30s ./main "https://$DOMAIN" "$FILENAME" > /dev/null 2>&1 
    
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 0 ]; then
        if [ -f "$FILENAME" ]; then
            mv "$FILENAME" "$OUTPUT_DIR/" 2>/dev/null
	else
	    echo "[ROUND $ROUND] $DOMAIN - File not found" >> "$FAILED_LOG"
	fi
    else
        echo "[ROUND $ROUND] $DOMAIN - Exit Code: $EXIT_CODE" >> "$FAILED_LOG"
	
        rm -f "$FILENAME" 2>/dev/null
    fi
}
export -f do_capture
export OUTPUT_DIR FAILED_LOG

# 3. 마라톤 시작
echo ">>> [System] Starting Parallel Capture: $ITERATIONS rounds per domain."
for ROUND in $(seq 1 $ITERATIONS); do
    echo ">>> ROUND $ROUND / $ITERATIONS"
    # xargs를 이용한 병렬 처리
    cat "$VALID_DOMAINS_FILE" | xargs -I {} -P $CONCURRENCY bash -c "do_capture {} $ROUND"
done

rm "$VALID_DOMAINS_FILE"
echo ">>> [System] Process Finished."
