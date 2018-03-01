import sys
import os
import argparse
import subprocess
import collections
import json

# The profiling record template
_ProfileRecord = collections.namedtuple('record', ['offset', 'func', 'timestamp'])


def main():
    binary, rules = process_args()
    args = {'binary': binary,
            'rules': rules}

    args = before(**args)
    args = collect(**args)
    args = after(**args)

    with open('profile.perf', 'w') as profile:
        json.dump(args['res'], profile, indent=4, ensure_ascii=False)


def before(**kwargs):
    kwargs['script'] = create_script(kwargs['binary'], kwargs['rules'])
    return dict(kwargs)


def collect(**kwargs):
    kwargs['out'] = run_script(kwargs['script'], kwargs['binary'])
    return dict(kwargs)


def after(**kwargs):
    kwargs['res'] = parse_output(kwargs['out'])
    return dict(kwargs)


def process_args():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('binary', help='The binary that will be traced')
        binary, rules = parser.parse_known_args()
        return os.path.realpath(binary.binary), rules
    except OSError:
        print('binary not found.')
        sys.exit(1)


def create_script(binary, rules):
    script = build_stap_script(binary, rules)

    script_path = binary + '_collect.stp'
    with open(script_path, 'w') as stp_handle:
        stp_handle.write(script)
    return script_path


def build_stap_script(binary, rules):
    script = ''
    for rule in rules:
        entry = 'probe process("' + binary + '").function("' + rule + '").call\n{\n'
        entry += '\tprintf("%s %s\\n", thread_indent(1), probefunc())\n}\n'
        ret = 'probe process("' + binary + '").function("' + rule + '").return\n{\n'
        ret += '\tprintf("%s\\n", thread_indent(-1))\n}\n'
        script += entry + ret
    return script


def run_script(script_path, binary):
    delim = script_path.rfind('/')
    if delim != -1:
        script_dir = script_path[:delim + 1]
        script_exec = script_path[delim + 1:]
    else:
        script_dir = ''
        script_exec = script_path

    try:
        output = script_dir + 'stap_record.txt'
        subprocess.check_call(('stap', '-v', script_exec, '-o', output, '-c', binary),
                              cwd=script_dir)
        return output
    except subprocess.CalledProcessError as exception:
        print('error code: ' + str(exception.returncode) + '\n')
        sys.exit(1)


# TODO: how about exceptions and stack unwinding?
def parse_output(output_path):
    with open(output_path, 'r') as trace:
        trace_stack = []
        resources = []
        sequence = 0
        for line in trace:
            record = _parse_record(line)
            if record.func:
                trace_stack.append(record)
            elif record.offset == trace_stack[-1].offset - 1:
                # Function exit, match with the function enter to create resources record
                matching_record = trace_stack.pop()
                resources.append({'amount': int(record.timestamp) - int(matching_record.timestamp),
                                  'uid': matching_record.func,
                                  'type': 'mixed',
                                  'subtype': 'time delta',
                                  'sequence': sequence})
                sequence += 1
            else:
                # error
                pass
        return resources


def _parse_record(line):
    parts = line.partition(':')
    time = parts[0].split()[0]
    right_section = parts[2].rstrip('\n')
    func = right_section.lstrip(' ')
    offset = len(right_section) - len(func)
    return _ProfileRecord(offset, func, time)


if __name__ == "__main__":
    main()
