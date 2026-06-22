# usbliter8-iboot-patchfinder

Universal iBoot/iBSS/iBEC patchfinder for A12/A13 jailbreak research, built for use with the [usbliter8](https://github.com/prdgmshift/usbliter8) BootROM exploit.

Automatically finds and patches security-critical targets in decrypted iBoot images. Works across all A12/A13 iPhones and iPads, iOS 17 through 27.

## Tools

### iboot_patchfinder.py

Full iBoot patchfinder with function discovery. Finds security targets via ADRP index + string xrefs, patches them, and identifies ~19 named functions.

```
$ python3 iboot_patchfinder.py iBoot.raw patched.raw --mode ibec

=== iBoot Patchfinder (mode=ibec, base=0x870000000) ===
  [1] image4_validate_property_callback — 2 patches
  [2] CTRR lockdown — 3 patches (NOP MSR CTRR_CTL/LOCK_EL2)
  [3] Boot-args — custom "serial=3 -v debug=0x2014e %s"
  [4] 19 functions identified
```

### iboot_patcher.py

Lightweight patcher (no function discovery). Same patches, faster execution.

## Patches

| # | Target | What it does | Method |
|---|--------|-------------|--------|
| 1 | `image4_validate_property_callback` | Bypass IMG4 signature verification | NOP b.ne + MOV X0, #0 at epilogue |
| 2 | CTRR lockdown | Keep kernel text writable after boot | NOP MSR CTRR_CTL_EL2 + CTRR_LOCK_EL2 |
| 3 | Boot-args | Inject `serial=3 -v debug=0x2014e %s` | Redirect ADRP+ADD to custom string |

### CTRR bypass — key insight

CTRR (Configurable Text Readonly Region) is locked by **iBoot, not BootROM**. Since usbliter8 provides code execution before iBoot runs, loading a patched iBoot that skips CTRR lockdown means the kernel text region stays writable — enabling classic NOP-style kernel patches on arm64e.

## Function discovery

The patchfinder identifies ~19 iBoot functions via string xrefs:

```
_panic                                        _main_task
_platform_get_usb_serial_number_string        _image4_register_callbacks
_image4_validate_property_callback             _UpdateDeviceTree
_check_autoboot                               _record_memory_range
_do_ramdisk                                   _do_devicetree
_sys_setup_default_environment                _platform_init_display
_boot_args_handler                            _aes_gid_key
_dart_init                                    _ctrr_handler
_ticket_verify
```

## Tested devices

| Device | iOS | Patches | Functions |
|--------|-----|---------|-----------|
| iPad 9th gen (A13) | 26.5 | 8 | 19 |
| iPad 9th gen (A13) | 27.0 beta | 8 | 19 |
| iPad Pro 2018/2020 (A12X/Z) | 26.5 | 8 | 19 |
| iPad Pro 2018/2020 (A12X/Z) | 27.0 beta | 8 | 19 |
| iPad Mini 5 / Air 3 (A12) | 26.5 | 8 | 19 |
| iPhone 11 (A13) | 26.5 | 14 | 19 |
| iPhone 11 (A13) | 27.0 beta | 14 | 19 |
| iPhone 11 Pro/Max (A13) | 26.5 | 14 | 19 |
| iPhone 11 Pro/Max (A13) | 27.0 beta | 14 | 19 |
| iPhone SE 2 (A13) | 26.5 | 14 | 19 |
| iPhone SE 2 (A13) | 27.0 beta | 14 | 19 |

11/11 devices, 100% success rate. iPads get 8 patches (different boot-args string layout), iPhones get 14.

## Requirements

```
pip install capstone
```

No other dependencies. Does not require keystone (uses pre-assembled instruction bytes).

## Usage with usbliter8

```bash
# 1. Decrypt iBoot from IPSW (iOS 26+ is unencrypted, older needs keys)
python3 -c "import pyimg4; ..."

# 2. Patch iBSS + iBEC
python3 iboot_patchfinder.py ibss.raw ibss_patched.raw --mode ibss
python3 iboot_patchfinder.py ibec.raw ibec_patched.raw --mode ibec

# 3. Load via usbliter8 after exploit
./usbliter8ctl boot ibss_patched.raw
```

## IDA integration

For deeper iBoot analysis in IDA, install [ida-iboot-loader](https://github.com/Orangera1n/ida-iboot-loader) — it auto-detects iBoot images, sets ARM64 processor, finds base address, and names ~30 functions.

## Related

- [usbliter8](https://github.com/prdgmshift/usbliter8) — A12/A13 SecureROM exploit by Paradigm Shift
- [usbliter8-kernel-patchfinder](https://github.com/Leeksov/usbliter8-kernel-patchfinder) — arm64e kernelcache patchfinder (20 targets)
- [usbliter8-txm-patchfinder](https://github.com/Leeksov/usbliter8-txm-patchfinder) — TXM patchfinder (code signing bypass, iOS 27)
- [usbliter8-sptm-patchfinder](https://github.com/Leeksov/usbliter8-sptm-patchfinder) — SPTM patchfinder (CTRR lockdown bypass)
- [ida-iboot-loader](https://github.com/Orangera1n/ida-iboot-loader) — IDA loader for iBoot/SecureROM

For research purposes only.

## License

MIT
