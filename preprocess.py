import os
import glob
import json
import binascii
from scapy.all import rdpcap, IP, TCP, UDP

def extract_pure_payload(pkt):
    """
    [논문 준수] Bias 제거를 위해 L2/L3/L4 헤더를 모두 날리고 Payload만 추출
    """
    try:
        if pkt.haslayer(TCP):
            raw_tcp = bytes(pkt[TCP])
            
            # 앞 4바이트(Src Port + Dst Port)만 잘라내고 나머지 반환
            return raw_tcp[4:]
            
        elif pkt.haslayer(UDP):
            raw_udp = bytes(pkt[UDP])
            
            # 앞 4바이트(Src Port + Dst Port)만 잘라냄
            return raw_udp[4:]
            
        elif pkt.haslayer(IP):
            # TCP/UDP가 없는 IP 패킷(ICMP 등)은 IP 헤더 제외하고 Payload만 사용
            return bytes(pkt[IP].payload)
        else:
            return b""
    except Exception as e:
        return b""

def payload_to_hex_bigrams(payload_bytes):
    """
    [구현체 호환] 2바이트씩 묶어서 16진수 문자열(예: 'dcfe')로 변환
    vocab.txt가 Hex로 되어있을 것이므로 이 형식을 따라야 함.
    """
    tokens = []
    # 2바이트씩 읽기 (Non-overlapping)
    for i in range(0, len(payload_bytes), 2):
        chunk = payload_bytes[i:i+2]
        if len(chunk) < 2: 
            # 마지막 1바이트가 남으면 00으로 패딩 (선택사항, 여기선 패딩)
            chunk += b'\x00'
        
        # 바이트를 Hex 문자열로 변환 (예: b'\xdc\xfe' -> "dcfe")
        hex_str = binascii.hexlify(chunk).decode('utf-8')
        tokens.append(hex_str)
        
    return tokens

def process_pcap_to_tsv(pcap_dir, output_tsv):
    pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcap"))
    domain_to_id = {}
    next_id = 0
    
    print(f"변환 시작: {pcap_dir} -> {output_tsv}")
    
    with open(output_tsv, 'w', encoding='utf-8') as f:
        # [중요] run_classifier.py가 요구하는 헤더 명칭 준수
        f.write("label\ttext_a\n")
        
        success_count = 0
        for pcap_path in pcap_files:
            # 파일명에서 라벨 추출 (파일명 형식: 유튜브_01.pcap 등 가정)
            # 사용자 환경에 맞게 수정 필요
            file_name = os.path.basename(pcap_path).replace(".pcap", "")
            parts = file_name.rsplit('_', 3)
            
            # 예외처리: 파일명 형식이 다르면 건너뜀
            if len(parts) < 2: 
                continue
                
            # 라벨 키 생성 (예: youtube)
            label_key = parts[0]
            
            if label_key not in domain_to_id:
                domain_to_id[label_key] = next_id
                next_id += 1
            
            try:
                pkts = rdpcap(pcap_path)
                flow_tokens = []
                packet_count = 0
                
                # Flow 구성: 상위 5개 패킷
                for p in pkts:
                    if packet_count >= 5: break
                    if IP not in p: continue
                    
                    # 1. 헤더 제거 (Payload만 추출)
                    payload = extract_pure_payload(p)
                    
                    if len(payload) == 0: continue
                    
                    # 2. Hex 토큰화
                    tokens = payload_to_hex_bigrams(payload)
                    flow_tokens.extend(tokens)
                    
                    packet_count += 1

                # 3. TSV 기록 (최대 길이 512 제한)
                if flow_tokens:
                    final_tokens = flow_tokens[:512]
                    combined_text = " ".join(final_tokens)
                    label_id = domain_to_id[label_key]
                    f.write(f"{label_id}\t{combined_text}\n")
                    success_count += 1
                    
            except Exception as e:
                print(f"Error: {pcap_path} - {e}")
                continue

    # 라벨 매핑 정보 저장 (나중에 결과 해석용)
    with open("label_mapping.json", "w", encoding='utf-8') as jf:
        json.dump(domain_to_id, jf, indent=4, ensure_ascii=False)
    
    print(f"완료! 총 {success_count}개 Flow 변환됨. (클래스 수: {len(domain_to_id)})")

if __name__ == "__main__":
    # 경로 수정 후 실행
    # 1. PCAP 파일들이 있는 폴더
    # 2. 저장할 TSV 파일 이름
    process_pcap_to_tsv("./captures", "my_train_dataset.tsv")