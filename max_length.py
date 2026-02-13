import os
import glob
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import PcapReader, IP, TCP, UDP, Raw
from multiprocessing import Pool, cpu_count

# ==========================================
# 설정
# ==========================================
INPUT_ROOT = "./splitcap"   # 정리된 PCAP 폴더
sample_ratio = 0.1          # 전체 다 하면 느리니 10%만 샘플링 (0.1 ~ 1.0)
# ==========================================

def get_payload_length(file_path):
    """
    PCAP 파일에서 유효한 페이로드(Hex)의 길이를 측정 (BERT Token 개수)
    ET-BERT 방식: 1 Byte = 1 Token (보통 2 Hex char)
    """
    tokens_count = []
    
    try:
        with PcapReader(file_path) as packets:
            for pkt in packets:
                # IP 패킷이고 TCP/UDP인 경우
                if IP in pkt and (TCP in pkt or UDP in pkt):
                    # Payload(Raw 레이어)가 있는 경우만
                    if Raw in pkt:
                        payload = pkt[Raw].load
                        # ET-BERT는 보통 Burst 단위로 자르지만, 
                        # 여기서는 패킷들의 총 페이로드 양을 확인합니다.
                        # 1 Byte = 1 Token
                        tokens_count.append(len(payload))
        
        if not tokens_count:
            return 0
            
        # 한 Flow(파일) 내의 모든 패킷 페이로드 합산 (Burst 길이 추정용)
        # 실제 ET-BERT 전처리는 양방향을 분리하거나 Burst 단위로 쪼개지만,
        # 전체적인 정보량을 보기 위해 합산 길이를 봅니다.
        return sum(tokens_count)

    except Exception:
        return 0

def main():
    print(f"토큰 길이 분석 시작 (Sample Ratio: {sample_ratio})...")
    
    search_pattern = os.path.join(INPUT_ROOT, "**", "*.pcap")
    all_files = glob.glob(search_pattern, recursive=True)
    
    # 샘플링
    import random
    random.shuffle(all_files)
    target_files = all_files[:int(len(all_files) * sample_ratio)]
    
    print(f"총 {len(target_files)}개 파일에 대해 분석 수행")

    lengths = []
    with Pool(cpu_count()) as pool:
        for length in pool.imap_unordered(get_payload_length, target_files):
            if length > 0:
                lengths.append(length)

    # 시각화
    lengths = np.array(lengths)
    
    print("\n[분석 결과]")
    print(f"평균 토큰 길이: {np.mean(lengths):.2f}")
    print(f"중앙값(Median): {np.median(lengths)}")
    print(f"최대 길이: {np.max(lengths)}")
    print(f"상위 90% 길이: {np.percentile(lengths, 90)}")
    print(f"상위 95% 길이: {np.percentile(lengths, 95)}")

    plt.figure(figsize=(12, 6))
    
    # 전체 분포 (Log Scale 권장 - 네트워크 트래픽은 롱테일 분포임)
    plt.subplot(1, 2, 1)
    plt.hist(lengths, bins=50, color='skyblue', edgecolor='black')
    plt.title("Token Length Distribution (Linear)")
    plt.xlabel("Length (Bytes/Tokens)")
    plt.ylabel("Count")

    plt.subplot(1, 2, 2)
    plt.hist(lengths, bins=50, color='salmon', edgecolor='black')
    plt.yscale('log') # 로그 스케일
    plt.title("Token Length Distribution (Log Scale)")
    plt.xlabel("Length (Bytes/Tokens)")
    
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()