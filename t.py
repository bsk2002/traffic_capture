import os
import glob

# ==========================================
# [설정] 실행 전 확인하세요!
# ==========================================
TARGET_ROOT = "./splitcap"  # 최상위 폴더 경로
DRY_RUN = True              # True: 삭제 안 하고 로그만 출력 / False: 실제 삭제
# ==========================================

def clean_duplicate_flows(root_dir):
    deleted_count = 0
    preserved_count = 0
    
    print(f"작업 시작: {root_dir}")
    if DRY_RUN:
        print("※ DRY_RUN 모드입니다. 실제 파일은 삭제되지 않습니다.\n")
    else:
        print("※ 주의: 실제 파일이 삭제됩니다.\n")

    # os.walk로 모든 하위 디렉토리를 재귀적으로 탐색
    for current_root, dirs, files in os.walk(root_dir):
        # 현재 폴더에 있는 .pcap 파일만 리스트업
        pcap_files = [f for f in files if f.endswith(".pcap")]
        
        # pcap 파일이 2개 이상인 경우에만 로직 수행
        if len(pcap_files) > 1:
            full_paths = []
            for f in pcap_files:
                path = os.path.join(current_root, f)
                size = os.path.getsize(path)
                full_paths.append((path, size, f))
            
            # 파일 크기순으로 내림차순 정렬 (가장 큰 파일이 0번 인덱스)
            full_paths.sort(key=lambda x: x[1], reverse=True)
            
            # 가장 큰 파일 (Winner)
            winner_path, winner_size, winner_name = full_paths[0]
            
            # 나머지 파일들 (Losers) -> 삭제 대상
            losers = full_paths[1:]
            
            print(f"[{os.path.basename(current_root)}] 파일 {len(pcap_files)}개 발견")
            print(f"  - 유지 (Main Flow): {winner_name} ({winner_size} bytes)")
            
            for loser_path, loser_size, loser_name in losers:
                if DRY_RUN:
                    print(f"  - [삭제 예정]: {loser_name} ({loser_size} bytes)")
                else:
                    try:
                        os.remove(loser_path)
                        print(f"  - [삭제 완료]: {loser_name}")
                        deleted_count += 1
                    except Exception as e:
                        print(f"  - [삭제 실패]: {loser_name} / 에러: {e}")
            print("-" * 50)
            
        if len(pcap_files) >= 1:
            preserved_count += 1

    print("\n" + "="*30)
    print("작업 종료 요약")
    print(f"처리된 폴더 수 (Flow 존재하는): {preserved_count}")
    if not DRY_RUN:
        print(f"삭제된 노이즈 파일 수: {deleted_count}")
    else:
        print(f"삭제 예정인 파일 수: {deleted_count}")
    print("="*30)

if __name__ == "__main__":
    clean_duplicate_flows(TARGET_ROOT)