# Coding by YES

import json
import socket
from prettytable import PrettyTable
from tqdm import tqdm
import re
import pandas as pd
import subprocess

class Winver_check:

    def __init__(self):
        super().__init__()

    def get_winver(self):

        command = "ver"
        process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        (result, err) = process.communicate()
        result = result.decode()

        dot_index = result.rfind('.')
        col_index = result.rfind(']')


        if 'Version 10' in result:
            self.win_num = 10
            self.build_num = result[dot_index - 5: dot_index]
            self.patch_num = result[dot_index + 1: col_index]

        elif 'Version 6.1' in result:
            self.win_num = 6.1
            self.build_num = 7601
            self.patch_num = 0

        return int(self.build_num), int(self.patch_num)

    def get_hotfix(self):
        command = "wmic qfe get hotfixID"
        process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        (result, err) = process.communicate()
        result = result.decode()

        hotfix = result.replace('\n', ' ').replace('HotFixID', '').replace(' KB', ' ')
        self.KB = hotfix.split()
        for i in range(0, len(self.KB)):
            self.KB[i] = int(self.KB[i])
        self.KB_max = max(self.KB)

        return self.KB_max

    def compare_winver(self):

        try:
            with open("./cve.json", "r") as f:
                self.j_data = json.load(f)
                if self.win_num == 10:
                    Win_list = self.j_data["WIN10_build"]
                    for win in Win_list:
                        for w in win:
                            if self.build_num in w:
                                update_ver = win[w]

                    print("\nOS ver : Windows 10 " + str(update_ver) + " [Build Num : "
                          + str(self.build_num) + "] [Patch Num : " + str(self.patch_num) + "]")
                    return str(update_ver), self.build_num, self.patch_num

                elif self.win_num == 6.1:
                    Win_list = self.j_data["WIN7_build"]
                    print("\nOS ver : Windows 7 Service Pack 1 NT 6.1 [Build Num : " + str(self.build_num) + "]")
                    return self.build_num

        except FileNotFoundError:
            print("Do you Have a Json File? => Check Json File")

class Port_Scanner:

    def __init__(self):
        super().__init__()

    # Ver 5.5
    def port_scan(self):
        command = 'netstat -a | findstr "127.0.0.1 0.0.0.0" | findstr TCP'
        process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        (result, err) = process.communicate()
        result = result.decode()

        print("\nPort Scanner Operating....")

        self.port = [139, 445, 3389, 8080]
        self.ports = re.findall(":..... ", result)

        self.po = []
        for p in tqdm(self.ports):
            p = p[1:].replace(" ", "")
            try:
                x = re.match('[0-9]{3,6}', p)
                self.po.append(int(x.group()))
            except AttributeError:
                pass
        self.po = list(set(self.po))
        self.open_port = []

        for p in self.port:
            if p in self.po:
                self.open_port.append(p)
            else:
                pass

        return self.open_port


class Vulerable_check(Winver_check, Port_Scanner):

    def __init__(self):
        super().__init__()

    def json_print(self, path, build_num, patch_num, KB_max):
        self.table = PrettyTable()
        self.table.field_names = ["CVE-ID", "Vulnerability Type", "Vulnerable Possiblity", "Target Port NUM",
                                  "CVSS Score", "Description"]

        self.data = []
        try:
            with open(path, "r") as f:
                self.json_data = json.load(f)
                cve_list = self.json_data["CVE"]

                for cve in cve_list:
                    for c in cve:
                        if c == 'CVE_name':
                            name = cve[c]

                        elif c == 'Vul_Type':
                            tp = cve[c]

                        elif c == 'port_num':
                            if type(cve[c]) is int:
                                cve[c] = [cve[c]]
                            port = cve[c]

                        elif c == "Description":
                            dec = cve[c]

                        elif c == "CVSS_Score":
                            score = cve[c]

                        elif (c == 'win10_patch_num') and build_num is not 7601:
                            try:
                                if type(cve[c]) is float:
                                    cve[c] = [cve[c]]
                                win10_check = ''
                                build_list = dict(cve[c])
                                for key in build_list:
                                    dot_index = str(key).rfind('.')
                                    build = (int(float(key)))
                                    patch = int(str(key)[dot_index + 1:len(str(key))])

                                    if build == build_num and (patch <= patch_num and build_list[key] <= KB_max):
                                        win10_check = "Safe"
                                    elif build == build_num and (patch > patch_num or build_list[key] > KB_max):
                                        win10_check = "Vulnerable"
                                    elif build < build_num:
                                        win10_check = "Safe"
                                    elif build > build_num:
                                        pass
                            except TypeError:
                                pass
                        
                        elif (c == 'win7_patch_num'):
                            try:
                                win7_check = ''
                                build_list = dict(cve[c])
                                hotfix = build_list['7601']
                                if hotfix >= KB_max:
                                    win7_check = 'Safe'
                                elif hotfix < KB_max:
                                    win7_check = "Vulnerable"
                            except TypeError:
                                pass

                    if (build_num != 7601) and (win10_check != ''):
                        self.table.add_row([name, tp, win10_check, port, float(score), dec])
                        self.data.append([name, tp, win10_check, port, float(score), dec])
                    elif (win7_check != '') and (build_num == 7601):
                        self.table.add_row([name, tp, win7_check, port, float(score), dec])
                        self.data.append([name, tp, win7_check, port, float(score), dec])

            print(self.table)
            return self.data

        #Json File이 없을때, 예외처리
        except FileNotFoundError:
            print("Do you Have a Json File? => Check Json File")


    def compare_port(self, ports):

        print("Open Vulnerable Port : " + str(ports))
        print()

    # Ver 5.5
    def CSVmake(self):
        df = pd.DataFrame(
            columns=['CVE-ID', 'Vulnerability Type', 'Vulnerable Possible', 'Target Port NUM', 'CVSS Score', 'Description'])
        df.to_csv('./CVE_list.csv')

        for d in self.data:
            df = pd.DataFrame([d])
            df.to_csv('./CVE_list.csv', mode='a', header=False, encoding='euc-kr')


# Main Function
if __name__ == '__main__':
    # Class 불러오기
    w_check = Winver_check()
    p_check = Port_Scanner()
    vul_check = Vulerable_check()

    max_hotfix = w_check.get_hotfix()
    ports = p_check.port_scan()                     # Port Scan
    win_ver = w_check.get_winver()                  # Windows Version Check
    ver = w_check.compare_winver()                  # Windows build num compare
    vul_check.compare_port(ports)                   # Port print
    data = vul_check.json_print("./cve.json", win_ver[0], win_ver[1], max_hotfix)    # Json Print
    #vul_check.CSVmake(data)						# CSV Creation
