"""Correlate the observed CMPF0 value with this diagnostic DLL's call site."""
import hashlib
import json
import subprocess
from pathlib import Path

import capstone
import pefile


def main():
    root = Path(__file__).resolve().parents[2]
    folder = root / 'build' / 'native-probe'
    dll = folder / 'probe.dll'
    module_result = subprocess.run([str(folder / 'controller.exe'), '--module-base', str(dll)],
                                   capture_output=True, text=True, check=True)
    module_base = int(module_result.stdout.strip(), 16)
    observed_value = 0x6b8c11ad
    image = pefile.PE(str(dll), fast_load=True)
    rva = observed_value - module_base
    candidate = image.get_data(rva - 2, 8)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    instructions = list(decoder.disasm(candidate, observed_value - 2))
    if not instructions or instructions[0].mnemonic != 'call' or instructions[0].size != 2:
        raise ValueError('Observed value does not follow the expected 2-byte call')
    report = dict(diagnostic_value=hex(observed_value), measured_reload_base=hex(module_base),
                  module_size=hex(image.OPTIONAL_HEADER.SizeOfImage), relative_address=hex(rva),
                  dll_sha256=hashlib.sha256(dll.read_bytes()).hexdigest(),
                  instruction_address=hex(instructions[0].address),
                  instruction=instructions[0].mnemonic + ' ' + instructions[0].op_str,
                  instruction_bytes=instructions[0].bytes.hex(),
                  following_instruction=(instructions[1].mnemonic + ' ' + instructions[1].op_str)
                  if len(instructions) > 1 else None,
                  limitation='DLL base was measured after the live experiment in a separate 32-bit process; '
                             'the mapping in the game was not independently logged during the experiment.')
    output = root / 'reports' / 'fake-send-thread-diagnostic' / 'cmpf0-caller-correlation.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
