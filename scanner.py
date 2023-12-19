# scanner.py
import os
import re
from termcolor import cprint
from tabulate import tabulate
from colorama import Fore
from colorama import Style

def banner():
    with open('banner.txt', 'r', encoding="utf8") as f:
        data = f.read()

    print(f'{Fore.GREEN}%s{Style.RESET_ALL}' % data)
    print("Providing you with Remote Code Execution Scanner for PHP and Python projects")
    print("Author: Lakshmi Priya, Bharani")

def scan(script_path, extension):
    vulnerabilities_results = []
    severity_results = []
    mitigation_results = []

    reg_php = r'\(([^)]+)\);'  # regular expression for PHP
    reg_py = r'\(([^)]+)\)'  # regular expression for Python
    unsafe_php = ["system", "shell_exec", "exec", "passthru", "eval", "include"]
    unsafe_python = ["os.system", "os.popen", "subprocess.Popen", "subprocess.call", "subprocess.run"]

    # Define a dictionary to score vulnerability severity and provide mitigation advice
    vulnerabilities = {
        "system": {"severity": 10, "mitigation": "Avoid using system functions. Use safer alternatives."},
        "shell_exec": {"severity": 10, "mitigation": "Avoid using shell_exec functions. Use safer alternatives."},
        "exec": {"severity": 10, "mitigation": "Avoid using exec functions. Use safer alternatives."},
        "passthru": {"severity": 10, "mitigation": "Avoid using passthru functions. Use safer alternatives."},
        "eval": {"severity": 8, "mitigation": "Avoid using eval functions. Validate and sanitize input."},
        "include": {"severity": 5, "mitigation": "Avoid using include functions. Use require_once and validate input."},
        "os.system": {"severity": 10, "mitigation": "Avoid using os.system functions. Use subprocess."},
        "os.popen": {"severity": 8, "mitigation": "Avoid using os.popen functions. Use subprocess."},
        "subprocess.Popen": {"severity": 8, "mitigation": "Sanitize and validate input passed to subprocess.Popen."},
        "subprocess.call": {"severity": 8, "mitigation": "Sanitize and validate input passed to subprocess.call."},
        "subprocess.run": {"severity": 6, "mitigation": "Sanitize and validate input passed to subprocess.run."}
    }

    if extension == 'php':
        unsafe = unsafe_php
        reg = reg_php
    elif extension == 'py':
        unsafe = unsafe_python
        reg = reg_py
    for root, dirs, files in os.walk(script_path, topdown=False):
        for fi in files:
            dfile = os.path.join(root, fi)
            if (extension == 'php' and dfile.endswith(".php")) or (extension == 'py' and dfile.endswith(".py")):
                with open(dfile, "r", encoding="utf-8") as f:
                    data = f.readlines()
                    for line_number, line in enumerate(data, start=1):
                        for unsafe_function in unsafe:
                            line_no = line.strip("\n")
                            final_reg = unsafe_function + reg
                            if bool(re.search(final_reg, line_no)):
                                vulnerability = vulnerabilities.get(unsafe_function, {"severity": 0, "mitigation": "No mitigation advice available."})
                                vulnerabilities_results.append([dfile, unsafe_function])
                                severity_results.append([dfile, unsafe_function, vulnerability["severity"]])
                                mitigation_results.append([dfile, unsafe_function, vulnerability["mitigation"]])


    # Sort the severity results by severity (in descending order)
    severity_results.sort(key=lambda x: x[2], reverse=True)

    return vulnerabilities_results, severity_results, mitigation_results
