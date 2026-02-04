import os
import shutil

def organize_pcap_files(directory_path):
    # 대상 디렉토리로 이동
    if not os.path.exists(directory_path):
        print(f"Error: {directory_path} 경로가 존재하지 않습니다.")
        return

    files = [f for f in os.listdir(directory_path) if f.endswith('.pcap')]

    for file_name in files:
        # 파일명에서 확장자 제외
        name_part = os.path.splitext(file_name)[0]
        
        # 오른쪽에서부터 '_'를 기준으로 3번 분리하여 name 추출
        # 구조: name + _rn + _숫자 + _숫자
        parts = name_part.rsplit('_', 3)
        
        if len(parts) < 4:
            print(f"Skip: {file_name} (형식이 맞지 않음)")
            continue
            
        folder_name = parts[0]
        target_folder = os.path.join(directory_path, folder_name)

        # 폴더 생성
        if not os.path.exists(target_folder):
            os.makedirs(target_folder)

        # 파일 이동
        source_path = os.path.join(directory_path, file_name)
        destination_path = os.path.join(target_folder, file_name)
        
        shutil.move(source_path, destination_path)
        print(f"Moved: {file_name} -> {folder_name}/")

if __name__ == "__main__":
    # .pcap 파일들이 있는 경로
    target_dir = "./captures" 
    organize_pcap_files(target_dir)
