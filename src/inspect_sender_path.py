"""Read-only, bounded disassembly of observed client send-path addresses."""
import argparse

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from emulate_capture_function import ReadOnlyProcess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--address', type=lambda text: int(text, 0), action='append', required=True)
    parser.add_argument('--length', type=int, default=192)
    args = parser.parse_args()
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    process = ReadOnlyProcess(args.pid)
    try:
        for address in args.address:
            try:
                code = process.read(address, args.length)
            except OSError as exc:
                print(f'{address:#010x}: {exc}')
                continue
            print(f'\n{address:#010x}:')
            for instruction in decoder.disasm(code, address):
                print(f'  {instruction.address:#010x} {instruction.mnemonic:7} {instruction.op_str}')
                if instruction.mnemonic in ('ret', 'retf', 'jmp'):
                    break
    finally:
        process.close()


if __name__ == '__main__':
    main()
