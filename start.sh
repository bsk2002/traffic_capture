#!/bin/bash

# --- 설정 구간 ---
CSV_FILE="cloudflare-radar_top-200-domains_20260119-20260126.csv"
BLACKLIST_FILE="failed_unique_domains.txt"
EXE="./main"
OUTPUT_DIR="./captures"
DROPPED_FILE="dropped_final.txt"
TEMP_PCAP_PATTERN="website_capture_*.pcap"

ITERATIONS=500  # 각 도메인당 목표 방문 횟수 (500라운드)

# 초기화
mkdir -p "$OUTPUT_DIR"
> "$DROPPED_FILE"

# 1. 블랙리스트 로드 (연관 배열 사용으로 속도 최적화)
declare -A BLACKLIST
if [ -f "$BLACKLIST_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        # 도메인 이름만 추출 (Round X: 부분 제거)
        clean_domain=$(echo "$line" | awk '{print $NF}' | xargs)
        if [ -n "$clean_domain" ]; then
            BLACKLIST["$clean_domain"]=1
        fi
    done < "$BLACKLIST_FILE"
    echo ">>> [System] Blacklist loaded: ${#BLACKLIST[@]} domains will be ignored."
fi

echo ">>> [System] Starting marathon: 500 captures per domain."

# 2. 500 라운드 반복
for ROUND in $(seq 1 $ITERATIONS); do
    echo "===================================================="
    echo ">>> ROUND $ROUND / $ITERATIONS STARTING"
    echo "===================================================="

    while IFS=, read -r RAW_DOMAIN || [ -n "$RAW_DOMAIN" ]; do
        # 도메인 전처리
        DOMAIN=$(echo "$RAW_DOMAIN" | tr -d '\r\n"' | xargs)
        if [[ -z "$DOMAIN" || "$DOMAIN" == "domain" ]]; then
            continue
        fi

        # 블랙리스트 체크: 블랙리스트에 있으면 시도조차 안 함
        if [[ ${BLACKLIST["$DOMAIN"]} ]]; then
            continue
        fi

        echo "----------------------------------------------------"
        echo "[Round $ROUND] Targeting: $DOMAIN"

        # HTTPS 시도 (setcap 권한이 있으므로 sudo 없이 실행)
        $EXE "https://$DOMAIN"
        EXIT_CODE=$?

        # 결과 처리
        LATEST_FILE=$(ls -t $TEMP_PCAP_PATTERN 2>/dev/null | head -n 1)

        if [ $EXIT_CODE -eq 0 ] && [ -n "$LATEST_FILE" ]; then
            echo "  [OK] Capture successful."
            SAFE_DOMAIN=$(echo "$DOMAIN" | tr '.' '_')
            TIMESTAMP=$(date +"%H%M%S")
            # 파일명에 도메인과 라운드 정보를 명시하여 저장
            mv "$LATEST_FILE" "$OUTPUT_DIR/${SAFE_DOMAIN}_R${ROUND}_${TIMESTAMP}.pcap"
        else
            echo "  [FAIL] Capture failed."
            echo "Round $ROUND: $DOMAIN" >> "$DROPPED_FILE"
            # 실패 시 생성된 쓰레기 파일 즉시 삭제
            [ -f "$LATEST_FILE" ] && rm -f "$LATEST_FILE"
        fi

        # 루프 끝날 때마다 혹시 모를 잔여 파일 청소
        rm -f website_capture_*.pcap 2>/dev/null
        
        # 서버 부하 방지용 짧은 휴식 (필요에 따라 조절)
        sleep 1.5

    done < "$CSV_FILE"

    echo ">>> Round $ROUND finished. Cooling down for 10 seconds..."
    sleep 10
done

echo "----------------------------------------------------"
echo ">>> [System] Marathon Complete! Check $OUTPUT_DIR for your dataset."