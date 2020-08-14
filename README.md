# SecretsScanner
Secrets scanner scans your code for secrets based on a secrets pattern file. The pattern file can also be used to define patterns to whitelist files, directories, string patterns and lines in files. Secrets found in these whitelisted items will be ignored.

Dependencies - This code was written and tested in python v3.8.5

Usage - 
1) Navigate to the directory where the SecretsScanner script is present. Remember to update the script with the root folder of the source code and the location of the secrets pattern json file.
3) Ensure that you have the script dependencies installed using pip (see the script code for the list of python packages to install) 
2) For a full scan of the codebase type:
   python3 SecretsScanner.py or python3 SecretsScanner.py --entire
3) For a scan of the merged/changed files only type (this feature is a work in progress):
   python3 SecretsScanner.py --partial
   

