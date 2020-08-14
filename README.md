# SecretsScanner
Secrets scanner scans your code for secrets based on a secrets pattern file. The pattern file can also be used to define patterns to whitelist files, directories, string patterns and lines in files. Secrets found in these whitelisted items will be ignored.

Dependencies - This code was written and tested in python v3.8.5

Usage - 
1) Navigate to the directory where the SecretsScanner script is present. Remember to update the script with the root folder of the source code and the location of the secrets pattern json file.
2) Ensure that you have the script dependencies installed using pip (see the script code for the list of python packages to install)
3) Update the secrets patterns file (pattern_file.json) to include your blacklist and whitelist patterns. The blacklist pattern is pretty exhaustive but you might want to include your custom patterns. You will however need to configure your custom whitelist patterns (allowed directories, files, string patterns and lines in files)
4) For a full scan of the codebase type:
   python3 SecretsScanner.py or python3 SecretsScanner.py --entire
5) For a scan of the merged/changed files only type (this feature is a work in progress):
   python3 SecretsScanner.py --partial
   

