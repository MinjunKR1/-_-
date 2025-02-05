import os
import pefile
import hashlib
from concurrent.futures import ThreadPoolExecutor

import time

from VirusTotalAPI import scan_file as sf
from VirusTotalAPI import results as scan_r

def analysis(directory_path):
    print("Executor 생성\n")
    # DFS 깊이 우선 탐색 알고리즘으로 변경
    with ThreadPoolExecutor() as executor:
        print("검역소 안 파일 탐색 중..\n")
        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)
            if os.path.isdir(file_path):
                analysis(file_path)
            elif os.path.isfile(file_path) and file_path.endswith('.exe'):
                executor.submit(analysis_file, file_path, filename)
                print("분석 시작 : {0}".format(file_path))

    # directory_path = r'{0}'.format(directory_path)

    # print("검역소 경로 : {0}".format(directory_path))

    # # 병렬 처리
    # print("Executor 생성\n")
    # with ThreadPoolExecutor() as executor: # executor 생성
    #     print("검역소 안에 있는 파일들을 검색하는중..\n")
    #     for filename in os.listdir(directory_path): # 파일 검색
    #         file_path = os.path.join(directory_path, filename)
    #         if os.path.isfile(file_path) and file_path.endswith('.exe'): # 파일 경로인지 exe 파일인지
    #             executor.submit(analysis_file, file_path, filename)
    #             print("분석 시작 : {0}".format(os.path.join(file_path, filename)))

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
