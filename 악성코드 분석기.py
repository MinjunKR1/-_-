import random
import os

from PE import main as PEmain

def makefolder():
    folder_name = str(random.randint(100000000, 1000000000-1))
    current_path = str(os.getcwd())

    folder_path = os.path.join(current_path, folder_name)

    os.mkdir(folder_path)

    return folder_path

def main():
    folder_path = makefolder()

    print("바이러스 검사를 위한 검역소 생성 완료.\nFolder Path : {0}".format(folder_path))

    check = str(input("악성코드 파일을 분석할 검역소를 생성 했습니다.\n위에 Folder Path에 있는 폴더에 악성코드를 넣으시고 enter키를 눌러서 분석을 시작해주세요.\n[Press Enter]"))

    PEmain(folder_path)

if __name__ == "__main__":
    main()