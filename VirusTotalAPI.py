# API key : 8a03cd3c66bd5662e46af819f6ed86a621fe72f72edd82b49d7c4d20c53ca0a6

import requests

import os
import time
import json

def scan_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"

    headers = {
        "accept": "application/json",
        "x-apikey": "8a03cd3c66bd5662e46af819f6ed86a621fe72f72edd82b49d7c4d20c53ca0a6"
    }

    with open(file_path, 'rb') as file:
        file_data = file.read()

    file_size = os.path.getsize(file_path)
    if file_size > 32 * 1024 * 1024:
        print(f"파일 크기가 {32 * 1024 * 1024 / (1024 * 1024)}MB를 초과하여 업로드할 수 없습니다. 파일 크기: {file_size / (1024 * 1024):.2f}MB")
        return None  # 파일 크기 초과시 업로드하지 않음

    response = requests.post(url, headers=headers, files={"file": (os.path.basename(file_path), file_data)})

    if response.status_code == 200:
        json_response = response.json()
        file_id = json_response['data']['id']
        print("분석 서버에 파일 업로드 : {0}".format(file_id))
        return file_id
    else:
        print("업로드 실패")

    print(response.text)

def results(file_id):
    while True:
        if not file_id:
            print("파일 ID가 없으므로 분석 결과를 확인할 수 없습니다.")
            return
        
        url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": "8a03cd3c66bd5662e46af819f6ed86a621fe72f72edd82b49d7c4d20c53ca0a6"
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            status = json_response.get('data', {}).get('attributes', {}).get('status', 'queued')
            if status == "completed":
                results = json_response.get('data', {}).get('attributes', {}).get('results', {})
                if not results:
                    print("결과가 없습니다.")
                else:
                    detected_results = []
                    undetected_results = []

                    for engine, result in results.items():
                        engine_name = result.get('engine_name', '알 수 없는 엔진')
                        engine_version = result.get('engine_version', '버전 정보 없음')
                        detection_result = result.get('category', '검사 결과 없음')

                        if detection_result == "malicious":
                            detected_results.append(f"{engine_name} ({engine_version}): {detection_result}")
                        else:
                            undetected_results.append(f"{engine_name} ({engine_version}): {detection_result}")

                    if detected_results:
                        print("\n[바이러스 발견된 엔진]")
                        for result in detected_results:
                            print(result)
                    else:
                        print("\n[바이러스 발견된 엔진]: 없음")

                    if undetected_results:
                        print("\n[바이러스 미검출 엔진]")
                        for result in undetected_results:
                            print(result)
                    else:
                        print("\n[바이러스 미검출 엔진]: 없음")

                break
            else:
                print("아직 검사가 다 완료 되지 않았습니다.\n검사가 완료 될때 까지 기다려주세요.\n15초 뒤에 자동으로 다시 검사 결과를 검색합니다.")
                time.sleep(15)
        else:
            print(f"API 요청 실패, 상태 코드: {response.status_code}")
            print(response.text)
            break
