import os
import glob
import json
import binascii
import random
from scapy.all import rdpcap, IP, TCP, UDP
from tqdm import tqdm

def extract_pure_payload(pkt):
    """
    [논문 준수] Bias 제거를 위해 L2/L3/L4 헤더를 모두 날리고 Payload만 추출
    (사용자 요청: TCP/UDP의 경우 Port(4바이트)만 제거하고 나머지 헤더 정보는 유지하는 로직)
    """
    try:
        # if pkt.haslayer(TCP):
        #     raw_tcp = bytes(pkt[TCP])
        #     # 앞 4바이트(Src Port + Dst Port)만 잘라내고 나머지 반환
        #     return raw_tcp[4:]
            
        # elif pkt.haslayer(UDP):
        #     raw_udp = bytes(pkt[UDP])
        #     # 앞 4바이트(Src Port + Dst Port)만 잘라냄
        #     return raw_udp[4:]
            
        # elif pkt.haslayer(IP):
        #     # TCP/UDP가 없는 IP 패킷(ICMP 등)은 IP 헤더 제외하고 Payload만 사용
        #     return bytes(pkt[IP].payload)
        # else:
        #     return b""
        return bytes(pkt)
    except Exception as e:
        return b""

def payload_to_hex_bigrams(payload_bytes):
    """
    [구현체 호환] 2바이트씩 묶어서 16진수 문자열(예: 'dcfe')로 변환
    """
    tokens = []
    # 2바이트씩 읽기 (Non-overlapping)
    for i in range(0, len(payload_bytes) - 1):
        chunk = payload_bytes[i:i+2]
        
        hex_str = binascii.hexlify(chunk).decode('utf-8')
        tokens.append(hex_str)
        
    return tokens

def process_and_split(pcap_dir, output_dir, split_ratio=(8, 1, 1)):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcap"))
    if not pcap_files:
        print("PCAP 파일이 없습니다.")
        return

    domain_to_id = {}
    next_id = 0
    all_dataset = []

    print(f"데이터 변환 시작 (Bi-gram Overlapping 적용)...")

    # tqdm으로 진행률 표시
    for pcap_path in tqdm(pcap_files, desc="Processing", unit="file"):
        file_name = os.path.basename(pcap_path).replace(".pcap", "")
        
        # 파일명 파싱 (name_Rn_time_time.pcap)
        # 오른쪽에서 3번 자름 -> [name, Rn, time, time]
        parts = file_name.rsplit('_', 3)
        label_key = parts[0] if len(parts) >= 2 else file_name

        if label_key not in domain_to_id:
            domain_to_id[label_key] = next_id
            next_id += 1
        
        try:
            pkts = rdpcap(pcap_path)
            flow_tokens = []
            packet_count = 0
            
            # Flow 구성 (상위 5패킷) [cite: 253]
            for p in pkts:
                if packet_count >= 5: break
                if IP not in p: continue
                
                # 1. 바이트 추출 (Port 제거)
                feature_data = extract_pure_payload(p)
                if len(feature_data) < 2: continue
                
                # 2. 토큰화 (겹치는 방식)
                tokens = payload_to_hex_bigrams(feature_data)
                flow_tokens.extend(tokens)
                packet_count += 1

            if flow_tokens:
                # 입력 길이 제한 (최대 512 토큰) [cite: 123]
                final_tokens = flow_tokens[:512]
                combined_text = " ".join(final_tokens)
                label_id = domain_to_id[label_key]
                
                # 메모리에 저장
                all_dataset.append(f"{label_id}\t{combined_text}\n")
                
        except Exception as e:
            # 에러 발생 시 건너뜀
            continue

    # 4. 데이터 분할 및 저장 (8:1:1) [cite: 295]
    print("\n데이터 분할 및 저장 중...")
    random.seed(42)
    random.shuffle(all_dataset)
    
    total = len(all_dataset)
    r_train, r_valid, r_test = split_ratio
    total_r = sum(split_ratio)
    
    idx1 = int(total * (r_train / total_r))
    idx2 = int(total * ((r_train + r_valid) / total_r))
    
    def save_file(name, data):
        with open(os.path.join(output_dir, name), 'w', encoding='utf-8') as f:
            f.write("label\ttext_a\n") # 헤더 필수
            f.writelines(data)
            
    save_file("train_dataset.tsv", all_dataset[:idx1])
    save_file("valid_dataset.tsv", all_dataset[idx1:idx2])
    save_file("test_dataset.tsv", all_dataset[idx2:])
    
    # 매핑 정보 저장
    with open(os.path.join(output_dir, "label_mapping.json"), "w", encoding='utf-8') as f:
        json.dump(domain_to_id, f, indent=4, ensure_ascii=False)

    print(f"완료! 총 {total}개 Flow 변환됨.")

if __name__ == "__main__":
    # 경로 설정
    process_and_split("./captures", "./split_output")