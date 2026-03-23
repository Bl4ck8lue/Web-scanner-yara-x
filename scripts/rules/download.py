import os
import sys
import json

def main():
    os.system('wget https://clamav-mirror.ru/main.cvd')
    os.system('sigtool -u main.cvd')
    os.system('python3.14 clamav_to_yara_py_3.py -f main.ndb -o downloaded_rules.yar')
    os.system('mv downloaded_rules.yar ./rules/')
    

if __name__ == '__main__':
    main()
