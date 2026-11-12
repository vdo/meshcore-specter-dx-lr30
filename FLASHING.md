# Flashing a DX-LR30 with Specter (USB serial)

Quick runbook. Full background is in the README's "Flashing" section.

## 1. Build

```bash
pio run -e specter            # or -e specter_custom for pre-configured builds
# -> .pio/build/specter/firmware.bin
```

The first build downloads the STM32 toolchain and stm32flash, so it takes a few minutes.

## 2. Find the port

```bash
ls /dev/cu.usbserial*         # macOS. Linux: /dev/ttyUSB*
```

The port name **changes after every replug** (for example `-210` became `-1220`), so check it each time.
Close anything else using the port (`pio ... -t monitor`, a config.meshcore.io tab,
screen). Otherwise you get `Resource busy`.

## 3. Enter the bootloader

- **New/vanilla board:** hold KEY, tap RST, release KEY.
- **Board already running Specter 1.15.1 or later:** `pio run -e specter -t monitor`, type `dfu`,
  press Ctrl-C, wait about 25 seconds.
- **Stubborn board:** see the README (repeat RST/KEY, or solder a wire to BOOT0).

You're in the bootloader when the **blue LED is off and not blinking**.

Optional read-only check (expect `sync reply: 79`, chip ID `0410`):

```bash
~/.platformio/penv/bin/python - <<'EOF'
import serial
s = serial.Serial('/dev/cu.usbserial-XXXX', 115200, parity=serial.PARITY_EVEN, timeout=1)
s.write(b'\x7f'); print('sync reply:', s.read(1).hex() or 'none')
EOF
```

> **Gotcha:** the STM32 bootloader locks onto the baud rate of the **first** sync byte it
> receives. Run the check at 115200 (as above) or the upload fails with
> `Failed to init device, timeout`. If that happens, either re-enter the
> bootloader or flash at the baud rate you probed with (`-b 57600`).

## 4. Flash

```bash
pio run -e specter -t upload --upload-port /dev/cu.usbserial-XXXX
```

or directly:

```bash
~/.platformio/packages/tool-stm32flash/stm32flash \
  -w .pio/build/specter/firmware.bin -v -g 0x08000000 /dev/cu.usbserial-XXXX
```

`-v` verifies the write. `-g 0x08000000` starts the firmware afterwards, so no reset is needed.

## 5. Verify and set up

```bash
pio run -e specter -t monitor --monitor-port /dev/cu.usbserial-XXXX
```

| Command | Purpose |
|---|---|
| `ver` | should print the build version and today's date |
| `set name <Name>` | node name used in adverts |
| `time $(date +%s)` | set the clock. Type the epoch number; the monitor doesn't expand `$(…)` |
| `get public.key` | 64-hex pubkey, for adding the node as a contact |

Or configure it in Chrome at https://config.meshcore.io.

### Contact QR

Add the node in the MeshCore app with this link (or a QR code of it):

```
meshcore://contact/add?name=<Name%20URL-encoded>&public_key=<64-hex, lowercase>&type=2
```

Put it in a QR code with any QR tool (for example `qrencode -t ANSIUTF8 '<url>'`). `type=2` = repeater.
