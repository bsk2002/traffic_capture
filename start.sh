#!/bin/bash

# --- 설정 구간 ---
CSV_FILE="cloudflare-radar_top-200-domains_20260119-20260126.csv"          # 도메인 목록 파일
EXE="./main"                    # 빌드된 Go 실행 파일 이름
OUTPUT_DIR="./captures"         # 성공한 pcap 저장 폴더
DROPPED_FILE="dropped.txt"      # 실패한 도메인 기록 파일
TEMP_PCAP_PATTERN="website_capture_*.pcap"

# 초기화
mkdir -p "$OUTPUT_DIR"
> "$DROPPED_FILE" # 기존 파일 비우기

echo ">>> [System] Starting automation for 200 domains..."

# --- 실행 구간 ---
while IFS=, read -r RAW_DOMAIN || [ -n "$RAW_DOMAIN" ]; do
    # 1. 전처리 (공백, 따옴표 제거)
    DOMAIN=$(echo "$RAW_DOMAIN" | tr -d '\r\n"' | xargs)
    
    # 빈 줄이나 헤더 제외
    if [[ -z "$DOMAIN" || "$DOMAIN" == "domain" ]]; then
        continue
    fi

    echo "----------------------------------------------------"
    echo "[Target] Domain: $DOMAIN"

    SUCCESS=false

    # 2. HTTPS 시도
    echo "  >> Trying https://$DOMAIN..."
    $EXE "https://$DOMAIN"
    
    if [ $? -eq 0 ]; then
        SUCCESS=true
        PROTOCOL="HTTPS"
    fi

    # 3. 결과 처리
    if [ "$SUCCESS" = true ]; then
        echo "  [OK] Successfully captured via https://$DOMAIN."
        
        # 파일명 변경 (가장 최근에 생성된 pcap 찾기)
        LATEST_FILE=$(ls -t $TEMP_PCAP_PATTERN 2>/dev/null | head -n 1)
        if [ -n "$LATEST_FILE" ]; then
            SAFE_DOMAIN=$(echo "$DOMAIN" | tr '.' '_')
            TIMESTAMP=$(date +"%H%M%S")
            mv "$LATEST_FILE" "$OUTPUT_DIR/${SAFE_DOMAIN}_${TIMESTAMP}.pcap"
        fi
    else
        # 5. 모든 시도 실패 시 기록
        echo "  [FAIL] HTTPS failed. Dropping."
        echo "$DOMAIN" >> "$DROPPED_FILE"

        [ -f "$LATEST_FILE" ] && rm -f "$LATEST_FILE"
    fi

    # 네트워크 대기 (서버 차단 방지)
    sleep 2

done < "$CSV_FILE"

echo "----------------------------------------------------"
echo ">>> [System] Process Finished."
echo ">>> Successful captures: $(ls $OUTPUT_DIR | wc -l)"
echo ">>> Dropped domains: $(wc -l < $DROPPED_FILE)"