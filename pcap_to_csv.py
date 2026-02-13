import os
import glob
import numpy as np
import pandas as pd
from scapy.all import PcapReader, IP
from multiprocessing import Pool, cpu_count
import time

# ==========================================
# 설정
# ==========================================
INPUT_ROOT = "./splitcap"   # 정리된 PCAP들이 있는 폴더
OUTPUT_CSV = "flow_stats_dataset.csv" # 결과로 나올 하나의 큰 CSV
NUM_WORKERS = cpu_count()
# ==========================================

def extract_flow_features(file_path):
    """
    PCAP 파일 하나를 읽어서 '하나의 통계 벡터(Row)'로 변환
    구조: splitcap/domain/domain_flow_folder/file.pcap
    """
    try:
        # 1. 경로 파싱
        # 예: splitcap/google_drive/google_drive_R1_0_0/traffic.pcap
        
        flow_dir = os.path.dirname(file_path)      # .../google_drive_R1_0_0
        domain_dir = os.path.dirname(flow_dir)     # .../google_drive
        label = os.path.basename(domain_dir)       # google_drive (정답 레이블)
        
        packet_sizes = []
        timestamps = []
        
        # Scapy로 스트리밍 읽기
        with PcapReader(file_path) as packets:
            for pkt in packets:
                if IP in pkt:
                    packet_sizes.append(len(pkt))
                    timestamps.append(float(pkt.time))
        
        if not packet_sizes:
            return None # 빈 파일 무시

        # 통계적 특징 계산 (Feature Engineering)
        packet_sizes = np.array(packet_sizes)
        timestamps = np.array(timestamps)
        
        # 패킷 길이 통계
        min_len = np.min(packet_sizes)
        max_len = np.max(packet_sizes)
        mean_len = np.mean(packet_sizes)
        std_len = np.std(packet_sizes)
        total_bytes = np.sum(packet_sizes)
        packet_count = len(packet_sizes)
        
        # 시간 통계 (Duration & IAT)
        duration = timestamps[-1] - timestamps[0]
        if packet_count > 1:
            iat = np.diff(timestamps) # Inter-Arrival Time
            mean_iat = np.mean(iat)
            std_iat = np.std(iat)
        else:
            mean_iat = 0
            std_iat = 0

        return {
            "label": label,            # 수정된 레이블 (도메인명)
            "pkt_count": packet_count,
            "total_bytes": total_bytes,
            "duration": duration,
            "min_len": min_len,
            "max_len": max_len,
            "mean_len": mean_len,
            "std_len": std_len,
            "mean_iat": mean_iat,
            "std_iat": std_iat
        }

    except Exception as e:
        # 디버깅을 위해 에러 로그 살짝 출력 (필요시 주석 해제)
        # print(f"Error in {file_path}: {e}")
        return None

def main():
    print(f"통계 데이터 추출 시작... (Workers: {NUM_WORKERS})")
    start_time = time.time()

    # 재귀적으로 모든 pcap 파일 탐색
    # splitcap/**/*.pcap
    search_pattern = os.path.join(INPUT_ROOT, "**", "*.pcap")
    pcap_files = glob.glob(search_pattern, recursive=True)
    
    print(f"총 {len(pcap_files)}개의 파일을 처리합니다.")

    # 병렬 처리
    data = []
    with Pool(NUM_WORKERS) as pool:
        for result in pool.imap_unordered(extract_flow_features, pcap_files):
            if result:
                data.append(result)
                
            if len(data) % 1000 == 0:
                print(f"진행 중... {len(data)}개 완료")

    # DataFrame 변환 및 저장
    df = pd.DataFrame(data)
    df.to_csv(OUTPUT_CSV, index=False)
    
    print(f"완료! 데이터가 {OUTPUT_CSV}에 저장되었습니다.")
    print(f"총 소요 시간: {time.time() - start_time:.2f}초")

if __name__ == "__main__":
    main()