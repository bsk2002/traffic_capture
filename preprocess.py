import os
import binascii
import glob
import json
from scapy.all import rdpcap, IP

def generate_et_bert_bigrams(hex_string, payload_len=128):
    """
   
    논문 규격: 인접한 두 바이트를 1바이트씩 이동하며 결합 (Sliding Window)
    예: DC FE 18 34 -> DCFE FE18 1834
    """
    # 2글자(1바이트)씩 리스트화
    bytes_list = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    
    bigrams = []
    # 중복 없이 인접 바이트를 결합하는 정확한 로직
    for i in range(len(bytes_list) - 1):
        if len(bigrams) >= payload_len: 
            break
        # i번째와 i+1번째 바이트를 결합
        combined = bytes_list[i] + bytes_list[i+1]
        bigrams.append(combined)
    
    return " ".join(bigrams)

def process_for_finetuning(pcap_dir, output_tsv):
    pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcap"))
    domain_to_id = {}
    next_id = 0
    
    # TSV 형식 준수
    with open(output_tsv, 'w', encoding='utf-8') as f:
        f.write("label\ttext_a\n")
        
        success_count = 0
        for pcap_path in pcap_files:
            file_name = os.path.basename(pcap_path).replace(".pcap", "")
            
            # 주소_Rn_날짜.pcap 파싱
            parts = file_name.split('_')
            if len(parts) < 3: continue
            domain_key = "_".join(parts[:-2]) # 주소 내 '_' 허용
            
            # Hashmap 등록
            if domain_key not in domain_to_id:
                domain_to_id[domain_key] = next_id
                next_id += 1
            
            try:
                pkts = rdpcap(pcap_path)
                flow_tokens = []
                
                # 상위 5개 패킷 사용
                for p in pkts[:5]:
                    if IP not in p: continue
                    
                    # 패킷 전체 바이트 추출 (Fine-tuning 예시 dcfe... 준수)
                    raw_hex = binascii.hexlify(bytes(p)).decode()
                    
                    tokenized = generate_et_bert_bigrams(raw_hex)
                    if tokenized:
                        flow_tokens.append(tokenized)

                if flow_tokens:
                    # 띄어쓰기로 토큰 구분하여 저장
                    combined_text = " ".join(flow_tokens)
                    f.write(f"{domain_to_id[domain_key]}\t{combined_text}\n")
                    success_count += 1
            except:
                continue

    # 모델 학습 시 활용할 도메인 맵 저장
    with open("domain_mapping.json", "w", encoding='utf-8') as jf:
        json.dump(domain_to_id, jf, indent=4, ensure_ascii=False)
    
    print(f"완료: {success_count}개 변환 성공 (도메인 종류: {len(domain_to_id)})")

if __name__ == "__main__":
    # 실제 pcap 폴더 경로로 수정 후 실행하세요.
    process_for_finetuning("./captures", "train_dataset.tsv")