# Native cipher investigation, 2026-11-21

The runtime reads use ordinary query/read process rights only. No debugger, injection, process writes, protection changes or packet sends. Experimental emulation writes affect only Unicorn memory. Snapshots and decoded data stay in ignored local reports.

## Verified S2C

- Capture: reports/network-20261121-134122/prime-relogin.pcapng.
- Callback 0x053874d4 invokes inner transform 0x053867ac. Decoded marker 0x8d selects persistent raw DEFLATE; inner records include full u16 LE lengths.
- Original native execution over all 1235 encrypted records: reports/decryption-20261121/emulation-server-sequence.json and server-sequence-snapshot/manifest.json, 90 demanded pages.
- Python matches every output hash AND every key state: native-python-equivalence.json. Full offline CLI: src/decode_prime_server.py.
- Counter at 0x053b5244 increments once per transformed server body. Initial 0 validated against the entire connection, with distinct lengths selecting different paths. Actual invoked standard helper 0x05386764 advances a u32 at key bytes 8..11. Earlier native helper 0x20466f60 uses u64, but is overridden and is not the basis of the final decoder.
- Do not infer that the first byte of the 17-byte key structure selects a no-op from early mode-0/mode-1 trials: those snapshots had different live packet counters. Returning an unchanged body can be the counter/length-dependent open mode.

## C2S result

Both directions now decode completely. Final commands/results are in decryption-progress.md. C2S: src/decode_prime_client_native.py consumes all 2902 encrypted bytes as 125 messages, removes one wrapper byte per message, outputs 2777 bytes, SHA-256 ea10861f872571e0e2b63196a12cb67bebb655ef139d377c705fbf190ba1bb7c. A fully offline repeat gives the same result. Each ciphertext body is reproduced exactly by the original encryption routine.

The crucial second counter is 0x053b5248, initialized to 0. Unlike S2C count 0x053b5244, this increments inside C2S transform and selects key rotation. Early C2S probes with live counter snapshots were invalid initial-state probes, not evidence of a different account format or impossible decoding.

Original 0x0538660c handles the body and advances the outgoing key. For 122 captured records it first reverses the plaintext bytes before XOR; 3 use direct XOR. The decoder builds the zero-input mask, tries the inverse, then re-encrypts with the original routine from the same key/counter and accepts only exact equality. It carries forward the key from that successful encryption, not the state produced by encrypting ciphertext as if it were plaintext.

The first wire size 64 yields initial length state low16 A8FC. All following lengths are decoded by state XOR; update low16 is ((state * decoded_wrapper_trailer) XOR state) + signed_opcode * encoded_body_length. State remains mod 65536. The entire direction parses without leftover bytes. Opcode 2B, the account field cross-match, slot 0 request, EnterWorld and the remaining command sequence validate this initial framing hypothesis.

Additional original page 0x05c80000 for the small-message path was retained in client-sequence-new-pages. The earlier outgoing snapshot and client-first-cipher-snapshot supply the other pages. Final offline decoder needs no game process. It executes only the cipher, never a send/recv API.

See offline-prime/exchange-verification.json for semantic validation: X501, account match (not printed), world ID 270128929 in CharacterSelected and all ten UserInfo, 9 client moves and 17 own-object server moves. Char-list record ID 199546 differs from world object ID; do not conflate them. UserInfo has the observed name at full-record offset 23 and world ID at 19.

## Earlier runtime exploration and retained probes

- PID 65124, Engine-like code base 0x20000000, custom callback allocation 0x05300000. No UI actions are needed.
- Root [0x208c5360] = UNetworkHandler at 0x1c0ac300. Its +0x48 points to active CClientSocket at 0xfce70000, +0x4c to auth socket at 0xfcea0000. These are valid readable WOW64 user addresses above 2 GiB. The early low-address-only searches missed them.
- CClientSocket vtable 0x205d326c, outgoing key structure +0x927c, incoming +0x928d. The 17-byte structures include a prefix byte then 16 key bytes. Do not print current session keys in user-visible output. A read-only private observation is runtime-high-address-socket.json.
- Native sender at 0x20466790 builds length+body and maps opcodes. At 0x20466833..0x2046684a it invokes override 0x05386d10 with (body, outgoing_key_structure, body_length), ECX=this. Return address 0x2046684c is material to reproducing the observed path. Standalone sentinel-return probes took a no-op path; they do not establish behavior of real calls.
- Send wrapper 0x05385c98 takes Winsock-style (socket, full_packet, full_length, flags). It eventually calls 0x05385c34, which calls stored original send via [[0x053a308c]]. Emulation stops at 0x05385c34 and never sends.
- A genuine current original-send trampoline is at 0xffba0ab8, a valid RWX private allocation, not an invalid kernel address. Earlier assumptions that all addresses above 2 GiB were unmapped were wrong. Do not bypass access failures; use ordinary queries.
- Outgoing callback + observed return boundary, followed by wrapper, reaches transformations 0x053869e0, 0x0538660c, 0x05386504 and changes key/buffer/header. Inner helper 0x053868e8 is a two-argument special-packet parser (checks FE/CB), not the general cipher.
- Isolated synthetic probe: 62-byte body with opcode 2B followed by zeros, initial key from captured S2C handshake, prefix 1, synthetic receiver. This is an algorithm probe, not a reconstruction of a real login packet. Observed internally that input length 62 becomes 63 for cipher 0x0538660c; investigate where the extra byte goes and how caller/send length changes.
- Latest successful probe: outgoing-caller-return.json/.blocks.json, outgoing-caller-return-snapshot/manifest.json, 643 demanded pages. It ends at 0x05385c34 with no emulator error. Body is no longer zero and the 16-byte key has changed. Actual C2S decoding is not yet established.
- Explicit extra observed pages needed for that exact probe: 0x753ce000 (kernel32 API code), 0x753b0000 (kernel32 header), 0x02aff000 and 0x006e4000 (readable process heap dependencies). No API stubs or instruction patches were used. Synthetic SEH cell maps address 0 with FFFFFFFF, so ordinary FS:[0] exception-chain setup is local to Unicorn.
- Global [0x053b5240] = 0x02affdf8 in that process. Its first u32 appears random and is read during outgoing setup; it is NOT established as a packet counter. It might be RNG state. Remaining bytes look like heap links. Do not reset it to zero based on the incoming counter.
- At last probe, first eight key bytes each XORed with C9, and last four changed independently. Cipher output over the zero body has a 16-byte repetition; length bytes receive additional processing. This is an observation, not a complete algorithm.

Reproduce the successful synthetic probe with no live reads by omitting --live-pid:

```powershell
python src/emulate_capture_function.py --capture reports/network-20261121-134122/prime-relogin.pcapng --runtime-path reports/decryption-20261121/emulation-runtime --entry 0x05386d10 --caller-return 0x2046684c --then-send-wrapper --socket-receiver --key-prefix-byte 1 --synthetic-body-size 62 --synthetic-opcode 0x2b --trace-record 1 --observed-read-page 0x753ce000 --observed-read-page 0x753b0000 --observed-read-page 0x02aff000 --observed-read-page 0x006e4000 --snapshot-dir reports/decryption-20261121/outgoing-caller-return-snapshot --report reports/decryption-20261121/outgoing-caller-return-offline.json
```

The emulator is experimental. Its `returned` flag means the original synthetic sentinel was reached; stopping at 0x05385c34 is intentionally reported false with no error. The primary server decoder has no emulator or process dependency.
