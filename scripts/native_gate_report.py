#!/usr/bin/env python3
"""Run real stable-Rust test binaries and emit fresh, fail-closed JUnit evidence.

No fixture labels or expected operation bodies enter this report. The harness
requires every listed native test to execute successfully; ignored, missing,
duplicate, or failed tests cannot satisfy an operational gate.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


def execute(command):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, check=False)
    if result.returncode:
        print(result.stdout, end='', file=sys.stderr)
        raise RuntimeError(f'native command failed with exit {result.returncode}')
    return result.stdout


def completed_tests(listing, output):
    expected = [line[:-6] for line in listing.splitlines() if line.endswith(': test')]
    if not expected or len(expected) != len(set(expected)):
        raise RuntimeError('empty or duplicate native test listing')
    observed = []
    for line in output.splitlines():
        match = re.fullmatch(r'test (.+) \.\.\. (.+)', line)
        if match:
            name, state = match.groups()
            if state != 'ok':
                raise RuntimeError(f'native test did not pass: {name}: {state}')
            observed.append(name)
    if len(observed) != len(set(observed)) or set(observed) != set(expected):
        raise RuntimeError('native report does not cover every listed test exactly once')
    if not re.search(r'test result: ok\. \d+ passed; 0 failed; 0 ignored;', output):
        raise RuntimeError('native completion summary missing or contains unmet tests')
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--test', action='append', default=[])
    parser.add_argument('--lib', action='store_true')
    parser.add_argument('--require-postgresql', action='store_true')
    args = parser.parse_args()
    if args.require_postgresql and not os.environ.get('DETERMA_TEST_POSTGRES_URL'):
        parser.error('DETERMA_TEST_POSTGRES_URL is required; PostgreSQL cannot be skipped')
    if len(args.test) != len(set(args.test)):
        parser.error('duplicate test binary')
    if not args.test and not args.lib:
        parser.error('at least one native test binary is required')
    requested = args.test + (['determa_state'] if args.lib else [])
    if len(requested) != len(set(requested)):
        parser.error('duplicate native binary name')
    command = ['cargo', 'test', '--locked', '--all-features', '--no-run', '--message-format=json']
    if args.lib:
        command.append('--lib')
    for name in args.test:
        command.extend(['--test', name])
    artifacts = {}
    for line in execute(command).splitlines():
        item = json.loads(line)
        if item.get('reason') == 'compiler-artifact' and item.get('executable'):
            target = item['target']
            if (target['name'] in requested
                    and target['kind'] == (['lib'] if target['name'] == 'determa_state' else ['test'])):
                if target['name'] in artifacts:
                    raise RuntimeError('duplicate native binary artifact')
                artifacts[target['name']] = item['executable']
    if set(artifacts) != set(requested):
        raise RuntimeError('not all requested native binaries were built')
    report = ET.Element('testsuites')
    for name in requested:
        binary = artifacts[name]
        listing = execute([binary, '--list', '--format=terse'])
        output = execute([binary, '--test-threads=1', '--format=pretty', '--color=never'])
        tests = completed_tests(listing, output)
        suite = ET.SubElement(report, 'testsuite', name=name, tests=str(len(tests)),
                              failures='0', errors='0', skipped='0', disabled='0')
        for test in tests:
            ET.SubElement(suite, 'testcase', classname=name, name=test, status='run')
        print(f'{name}: {len(tests)} native tests passed')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents stale evidence from being silently replaced.
    with args.report.open('xb') as destination:
        ET.ElementTree(report).write(destination, encoding='utf-8', xml_declaration=True)


if __name__ == '__main__':
    main()
