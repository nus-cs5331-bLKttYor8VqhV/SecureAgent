#!/usr/bin/env python3

import subprocess
from shutil import which
from sys import exit, stderr
from typing import List, Union, Tuple
from pathlib import Path
from glob import glob
from itertools import product
from functools import reduce


def find_source_files() -> List[str]:
    directories = ['enclave', 'host']
    extensions = ['.c', '.cc', '.cxx', '.cpp', '.h', '.hpp']

    return reduce(list.__add__, [
        glob(f'{d}/*{e}') for d, e in product(directories, extensions)
    ])


def find_compilation_database() -> str:
    cc = glob('**/compile_commands.json') or glob('compile_commands.json') or glob('**/compile_commands.json')
    if len(cc) == 0:
        print('Cannot find compile_commands.json in current project', file=stderr)
        print('    mkdir build && cd build && cmake ..', file=stderr)
        exit(1)

    return cc[0]


def find_executable(*args) -> str:
    result = ''
    for name in args:
        result = result or which(name)

    if not result:
        print(f'Cannot find {args[0]}', file=stderr)
        print(f'    sudo apt install {args[0]}', file=stderr)
        exit(1)

    return result


def diff_index():
    # A: addition of a file
    # C: copy of a file into a new one
    # M: modification of the contents or mode of a file

    p = subprocess.run(['git', 'diff-index', '--cached', '--name-status', 'HEAD'], stdout=subprocess.PIPE)
    stdout = p.stdout.decode().strip().splitlines()
    print(stdout)
    return [line[1:].strip() for line in stdout if line[0] in 'ACM']


def clang_tidy(build_path: str, source_files: List[str]):
    e = find_executable('clang-tidy-10', 'clang-tidy-8')
    p = subprocess.run([e, '-quiet', '-p', build_path, "-warnings-as-errors='*'"] + src)
    try:
        p.check_returncode()
    except subprocess.CalledProcessError as err:
        print('*' * 60, file=stderr)
        print('Please fix the errors above', file=stderr)
        print('*' * 60, file=stderr)
        exit(1)


def git_clang_format(build_path: str, source_files: List[str]):
    e = which('clang-format-10') and which('git-clang-format-10')
    p = subprocess.run([e, '--', '-p'] + source_files, stdout=subprocess.PIPE)
    try:
        p.check_returncode()
    except subprocess.CalledProcessError as err:
        print('*' * 60, file=stderr)
        print('Error found when running', ' '.join(p.args), file=stderr)
        print('Please fix the errors above', file=stderr)
        print('*' * 60, file=stderr)
        exit(1)

    stdout = p.stdout.decode().strip().splitlines()
    print(*stdout, sep='\n')

    if stdout[0] == 'changed files:':
        for fn in stdout[1:]:
            try:
                p = subprocess.run(args)
                p.check_returncode()
            except Exception as e:
                print('*' * 60, file=stderr)
                print('Exception when running', ' '.join(p.args), file=stderr)
                print(e)
                print('*' * 60, file=stderr)
                exit(1)


if __name__ == '__main__':
    src = [fn for fn in diff_index() if fn in find_source_files()]
    print(src)
    if len(src) > 0:
        cc = find_compilation_database()
        clang_tidy(cc, src)
        git_clang_format(cc, src)
