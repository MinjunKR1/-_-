import os
import pefile
import hashlib
from concurrent.futures import ThreadPoolExecutor

import time

from VirusTotalAPI import scan_file as sf
from VirusTotalAPI import results as scan_r

# directory_path = r'C:\Users\jysow\Desktop\고등학교 포트폴리오\악성코드 분석기\exe'

# directory_path = str(input("악성코드 파일을 분석할 격리 폴더를 생성 했습니다.\n파일을 넣으시고 enter키를 눌러서 분석을 시작해주세요.\n[Press Enter]"))

def analysis(directory_path):
    directory_path = r'{0}'.format(directory_path)

    print("검역소 경로 : {0}".format(directory_path))

    # 병렬 처리
    print("Executor 생성\n")
    with ThreadPoolExecutor() as executor: # executor 생성
        print("검역소 안에 있는 파일들을 검색하는중..\n")
        for filename in os.listdir(directory_path): # 파일 검색
            file_path = os.path.join(directory_path, filename)
            if os.path.isfile(file_path) and file_path.endswith('.exe'): # 파일 경로인지 exe 파일인지
                executor.submit(analysis_file, file_path, filename)
                print("분석 시작 : {0}".format(os.path.join(file_path, filename)))

# 악성코드 분석
def analysis_file(file_path, filename):
    pe = pefile.PE(file_path) # pe파일 분석

    md5_hash = hashlib.md5() # 해시 값 분석
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            md5_hash.update(chunk)
        md5_checksum = md5_hash.hexdigest()

        file_info = { # 핵심 파일 정보들 분석
            'filename' : filename,
            'entry_point' : pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'image_base' : hex(pe.OPTIONAL_HEADER.ImageBase),
            'md5_hash' : md5_checksum,
        }
        print("\n분석 종료 : {0}".format(os.path.join(file_path, filename)))
        # print("\n분석 결과\n>> {0}".format(file_info))

        file_id = sf(file_path)
        time.sleep(15)
        if file_id:
            scan_r(file_id)
            time.sleep(15)
 
        pe.close()

def main(directory_path):
    print("악성코드의 구조를 분석 하고 있습니다. 시간이 몇분 정도 소요 할 수 있습니다.\n\n프로그램을 종료하지 말아주세요.\n\n")
    analysis(directory_path)