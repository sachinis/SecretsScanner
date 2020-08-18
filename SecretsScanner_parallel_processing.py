import re
import os
import time
import subprocess
import json
import argparse
from concurrent.futures import ProcessPoolExecutor


class SecretsScanner(object):
    SOURCE_ROOT_DIRECTORY = '<<Enter root folder of our source code here?>>'
    PATTERN_FILE = '<<Enter location of pattern_file.json here>>'
    
    def __init__(self):
        self.file_list = []
        self.block_pattern = []
        self.allowed_string_pattern = []
        self.allowed_dirs = []
        self.allowed_files = []
        self.allowed_lines_pattern = []
        self.allowed_lines = []
        self.secrets = []
        self.changed_files = []
        self.scanned_file = []
        self.generate_patterns()
        self.count = 0
    
    def generate_patterns(self):
        with open(self.PATTERN_FILE) as f:
            pattern = json.load(f)
            self.block_pattern = pattern["Block_Pattern"]
            self.allowed_string_pattern = pattern["Allow_String_Pattern"]
            self.allowed_dirs = pattern["Allow_Dir"]
            self.allowed_files = pattern["Allow_File"]
            self.allowed_lines_pattern = pattern["Allow_File_Line"]
        for pattern in self.allowed_lines_pattern:
            self.allowed_lines.append((pattern.split(':$~')[0], pattern.split(':$~')[1]))
    
    def full_scan(self, root=SOURCE_ROOT_DIRECTORY):
        for dirpath, dirs, files in os.walk(root):
            # Logic to not scan whitelisted directories in pattern_file.json
            for adir in self.allowed_dirs:
                if re.match(adir, dirpath):
                    dirs[:] = []
                    files[:] = []
            for file in files:
                # Logic to not scan whitelisted files in pattern_file.json
                if os.path.join(dirpath, file) not in self.allowed_files:
                    self.file_list.append(os.path.join(dirpath, file))
        with ProcessPoolExecutor(max_workers=8) as executor:
            results = executor.map(self.find_secrets, self.file_list)
        self.secrets = [result for result in results if result is not None]
        return self.secrets
    
    # This method is a work in progress. Need to find the exact git command to get the list of merged files in a MR
    def partial_scan(self):
        # tgt_branch = os.environ.get('CI_MERGE_REQUEST_TARGET_BRANCH_SHA')
        # cmd = f'git diff-tree --name-only --no-commit-id {tgt_branch}'
        # modified_files = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        # if modified_files.returncode == 0:
        #     # Parse the output from the  command to get changed files
        #     self.changed_files.append(file)
        # return self.changed_files
        changed_files = ['/Users/tester/Documents/python-playground/test.txt',
                         '/Users/tester/Documents/python-playground/secret-test.txt',
                         '/Users/tester/Documents/python-playground/package_info.json',
                         '/Users/tester/Documents/python-playground/TestScript1.py',
                         '/Users/tester/Documents/python-playground/FileSystemService.py',
                         '/Users/tester/Documents/python-playground/new_homes.csv'
                         ]
        # Logic to not scan whitelisted directories in pattern_file.json
        for adir in self.allowed_dirs:
            for index, item in reversed(list(enumerate(changed_files))):
                if re.match(adir, item):
                    del changed_files[index]
        # Logic to not scan whitelisted files in pattern_file.json
        for file in self.allowed_files:
            for index, item in reversed(list(enumerate(changed_files))):
                if re.match(file, item):
                    del changed_files[index]
        with ProcessPoolExecutor(max_workers=8) as executor:
            results = executor.map(self.find_secrets, changed_files)
        self.secrets = [result for result in results if result is not None]
        return self.secrets
    
    # Finding secrets in files based on block patterns in pattern_file.json
    def find_secrets(self, filepath):
        if filepath not in self.scanned_file:
            self.scanned_file.append(filepath)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for num, line in enumerate(f.readlines()):
                        for bpattern in self.block_pattern:
                            pattern = re.compile(bpattern)
                            matches = pattern.finditer(line)
                            for match in matches:
                                print(f'{match.group(0)} FOUND BY PATTERN {bpattern}'
                                      f' IN FILE {filepath} ON LINE {num+1}')
                                return (filepath, match.group(0), num + 1)
            except (UnicodeDecodeError, PermissionError, FileNotFoundError) as e:
                pass
    
    def purge_allowed_patterns(self, secrets):
        # Purging secrets matching allowed patterns in pattern_file.json from secrets list
        for apattern in self.allowed_string_pattern:
            for index, item in reversed(list(enumerate(secrets))):
                if re.match(apattern, item[1]):
                    print(f'Deleting secret "{item[1]}" in file {item[0]}'
                          f' on line {item[2]} due to allowed pattern "{apattern}"')
                    self.count += 1
                    del secrets[index]
        # Purging secrets found in whitelisted file lines from secrets list
        for value in self.allowed_lines:
            for index, item in reversed(list(enumerate(secrets))):
                if re.match(value[0], item[0]) and int(value[1]) == int(item[2]):
                    self.count += 1
                    print(f'Deleting secret {secrets[index]}'
                          f' in allowed line {value[1]} in file {value[0]}')
                    del secrets[index]
        return self.get_results(secrets)
    
    def get_results(self, secrets):
        if len(secrets) > 0:
            return secrets
        else:
            return None


def main():
    t1 = time.perf_counter()
    parser = argparse.ArgumentParser(
        description="Pattern based secrets scanner",
        epilog='''
        1) For scanning the entire codebase --> python3 SecretsScanner.py -e
        2) For scanning partial/merged list of files --> python3 SecretsScanner.py -p'''
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', '--entire', help='Scans the entire code base', action='store_true', required=False)
    group.add_argument('-p', '--partial', help='Scans only the changed/merged files', action='store_true',
                       required=False)
    args = parser.parse_args()
    obj = SecretsScanner()
    if args.entire:
        print('-' * 65)
        print(f'Starting full scan and finding secrets based on block patterns')
        print('-'* 65)
        secrets = obj.full_scan()
        print('-' * 65)
        print(f'Starting purge of allowed patterns')
        print('-' * 65)
        if secrets is not None:
            results = obj.purge_allowed_patterns(secrets)
        else:
            results = None
    elif args.partial:
        print('-' * 65)
        print(f'Starting partial scan and finding secrets based on block patterns')
        print('-' * 65)
        secrets = obj.partial_scan()
        print(f'Total secrets found by block pattern before purge by allowed pattern = '
              f'{len(secrets) if secrets else 0}')
        print('-' * 65)
        print(f'Starting purge of allowed patterns')
        print('-' * 65)
        if secrets is not None:
            results = obj.purge_allowed_patterns(secrets)
        else:
            results = None
    else:
        print('-' * 65)
        print(f'Starting full scan and finding secrets based on block patterns')
        print('-' * 65)
        secrets = obj.full_scan()
        print(f'Total secrets found by block pattern before purge by allowed pattern = {len(secrets)}')
        print('-' * 65)
        print(f'Starting purge of allowed patterns')
        print('-' * 65)
        if secrets is not None:
            results = obj.purge_allowed_patterns(secrets)
        else:
            results = None
    if results:
        print('-' * 65)
        print('Final result(s) from Secret Scanning')
        print('-' * 65)
        for index, (filename, text, line_num) in enumerate(results):
            msg = f'~~~~ {index+1} - Secret "{text}" found in "{filename}" in line number : {line_num} ~~~~'
            print(msg)
        t2 = time.perf_counter()
        print(f'Time taken for the script to complete execution = {round((t2 - t1),2)} second(s)')
        exit(1)
    else:
        print('No secrets were found')
        t2 = time.perf_counter()
        print(f'Time taken for the script to complete execution = {round((t2 - t1),2)} second(s)')
        exit(0)


if __name__ == "__main__":
    main()
