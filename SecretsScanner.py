import re
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
import json
import argparse
import time


class SecretsScanner(object):
    SOURCE_ROOT_DIRECTORY = '<<<ENTER THE ROOT DIRECTORY THAT CONTAINS YOUR SOURCE CODE HERE>>>'
    PATTERN_FILE = '<<<ENTER THE ABSOLUTE LOCATION WHERE YOU HAVE STORED THE SECRETS PATTERN FILE>>>'

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
        self.generate_pattern_list()
        self.count = 0

    def generate_pattern_list(self):
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
            with ThreadPoolExecutor(max_workers=10) as executor2:
                executor2.map(self.find_secrets, self.file_list)

    # This method is a work in progress. Need to find the exact git command to get the list of merged files in a MR
    def partial_scan(self):
        # tgt_branch = os.environ.get('CI_MERGE_REQUEST_TARGET_BRANCH_SHA')
        # cmd = f'git diff-tree --name-only --no-commit-id {tgt_branch}'
        # modified_files = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        # if modified_files.returncode == 0:
        #     # Parse the output from the  command to get changed files
        #     self.changed_files.append(file)
        # return self.changed_files
        changed_files = ['/Users/testuser/test.txt', '/Users/testuser/test.csv']
        with ThreadPoolExecutor(max_workers=10) as executor2:
            executor2.map(self.find_secrets, changed_files)

    def find_secrets(self, filepath):
        # Finding secrets in files based on block patterns in pattern_file.json
        if filepath not in self.scanned_file:
            self.scanned_file.append(filepath)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for num, line in enumerate(f.readlines()):
                        for bpattern in self.block_pattern:
                            pattern = re.compile(bpattern)
                            matches = pattern.finditer(line)
                            for match in matches:
                                self.secrets.append((filepath, match.group(0), num + 1))
                                print(f'{len(self.secrets)} - {match.group(0)} '
                                      f'FOUND IN {self.secrets[-1][0]} BY PATTERN {bpattern}')
            except (UnicodeDecodeError, PermissionError) as e:
                pass

    def purge_allowed_patterns(self):
        # Purging secrets matching allowed patterns in pattern_file.json from self.secrets list
        for apattern in self.allowed_string_pattern:
            for index, item in enumerate(self.secrets):
                if re.findall(apattern, item[1]):
                    self.count += 1
                    print(f'{self.count} - Deleting allowed string {apattern} '
                          f'from file {self.secrets[index][0]}')
                    del self.secrets[index]
        # Purging secrets found in whitelisted file lines from self.secrets list
        for value in self.allowed_lines:
            for index, item in enumerate(self.secrets):
                if value[0] == item[0] and int(value[1]) == int(item[2]):
                    self.count += 1
                    print(f'{self.count} - Deleting allowed line {value[1]} in file {value[0]}')
                    del self.secrets[index]

    def get_results(self):
        self.purge_allowed_patterns()
        if len(self.secrets) > 0:
            return self.secrets
        else:
            return None


def main():
    t1 = time.perf_counter()
    parser = argparse.ArgumentParser(
        description="Pattern based secrets scanner",
        epilog='''
        1) For scanning the entire codebase --> python3 SecretsScanner.py -f
        2) For scanning partial/merged list of files --> python3 SecretsScanner.py -p'''
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', '--entire', help='Scans the entire code base', action='store_true', required=False)
    group.add_argument('-p', '--partial', help='Scans only the changed/merged files', action='store_true',
                       required=False)
    args = parser.parse_args()
    obj = SecretsScanner()
    if args.entire:
        print('-' * 50)
        print(f'Debug Message : Starting full scan and finding block patterns')
        print('-'*50)
        obj.full_scan()
        print('-' * 50)
        print(f'Debug Message : Starting purge of allowed patterns')
        print('-' * 50)
        results = obj.get_results()
    elif args.partial:
        print('-' * 50)
        print(f'Debug Message : Starting partial scan and finding block patterns')
        print('-' * 50)
        obj.partial_scan()
        print('-' * 50)
        print(f'Debug Message : Starting purge of allowed patterns')
        print('-' * 50)
        results = obj.get_results()
    else:
        print('-' * 50)
        print(f'Debug Message : Starting full scan and finding block patterns')
        print('-' * 50)
        obj.full_scan()
        print('-' * 50)
        print(f'Debug Message : Starting purge of allowed patterns')
        print('-' * 50)
        results = obj.get_results()
    if results:
        print('-'*50)
        print('Results from Secret Scanner')
        print('-' * 50)
        for index, (filename, text, line_num) in enumerate(results):
            msg = f'~~~~ {index+1} - Secret "{text}" found in "{filename}" on line number : {line_num} ~~~~'
            print(msg)
        exit(1)
    else:
        print('No secrets were found')
        exit(0)
    t2 = time.perf_counter()
    print(f'Scanned {len(obj.scanned_file)} files in {round(t2-t1,2)} seconds')


if __name__ == "__main__":
    main()
