# Exynos 9820 / BCM4375 Wi-Fi bring-up

Recovery enumerates a Broadcom endpoint at `0000:01:00.0`: vendor/device
`14e4:4475`, subsystem `14e4:4375`, PCI revision `05`. Its current kernel log
records a successful Gen1 link and a Broadcom chip ID of `0x4375`, then an
intentional power-off during DHD initialization. Cached sysfs PCI IDs alone do
not prove that the link remains up. This evidence establishes the transport
and device family, not functioning Wi-Fi under XNU.

## First XNU checkpoint

`b2l_wifi_diag=1` takes one snapshot before launchd of shared PMU, GPIO and
CMU registers. Missing, zero and unsupported values disable the probe before
mapping any register. The diagnostic profile does not select it. Lines have
the `B2L WIFI:` prefix and are retained in the existing persistent console.

This read-only mode completed on the phone in epoch 48, followed by launchd,
frame presentation and user-confirmed menu interaction. PHY isolation bypass
was zero; WLAN_REG_ON, PERST and CLKREQ were inputs with low sampled levels.
All six sampled gate words were `0x200000`, and all five QCH words were
`0x3f0002`. The preceding epoch ended during cache verification before reaching
this checkpoint. Allow at least five minutes before testing menu interaction
and returning to recovery; seeing an image alone is insufficient evidence.

The snapshot maps these four shared blocks with I/O memory attributes and
releases all mappings, including after a partial mapping failure. Mapping
lengths are 16 KiB and bases are aligned, accommodating the current 4 KiB
kernel and 16 KiB page granularity. Reads are aligned 32-bit accesses.

| Block | Base | Sampled offsets / purpose |
| --- | --- | --- |
| PMU | `0x15860000` | `0x71c`, channel-zero PHY isolation bypass bit 0 |
| PERIC0 GPIO | `0x10430000` | GPG0 CON/DAT `0x80/0x84`, WLAN_REG_ON pin 5 |
| FSYS1 GPIO | `0x13c40000` | GPF2 CON/DAT `0x20/0x24`, PERST pin 2 and CLKREQ pin 0 |
| CMU_FSYS1 | `0x13c00000` | PCIe gate words `0x2030..0x2044` and QCH words `0x3034..0x3044`, stride 4 |

Six gate words correspond to DBI, PHY SCL APB, master AXI, controller APB,
PCS APB and slave AXI. Five QCH words correspond to APB, DBI, master, PCS and
PHY. They are printed raw: automatic clock gating makes a single bit
insufficient to prove safe controller access. An all-ones PMU/GPIO register
stops decoding and releases mappings. Mapping success does not itself prove
that a register is readable; physical execution is still required.

No controller ELBI, PHY, PCS, DBI, configuration window or BAR is mapped or
read. Mode 1 writes no GPIO, clock, reset, isolation, ATU, interrupt, SysMMU or
PCI command register. No firmware is loaded and no network interface is
registered. A completed snapshot means only that this limited checkpoint ran.

## Temporary power-path checkpoint

`b2l_wifi_diag=2` first takes the same
snapshot, then accepts only the measured idle pin/isolation state and exact
clock words above. Any mismatch skips the active part without writes.

It preloads a low PERST data latch and makes that pin an output, preloads a
low WLAN_REG_ON latch and makes that pin an output, then raises WLAN_REG_ON.
After Samsung's 200 ms turn-on delay it briefly enables channel-zero PHY
isolation bypass and checks the shared-register readback. PERST stays low.
The chip is held in reset throughout the power pulse.

On success or a failed readback it attempts restoration of every owned bit:
PHY isolation, power/reset data, then the two pin function fields. Each
restoration is verified and retried at most three times. A failed restoration
is explicitly logged. Read-modify-write operations preserve all other bits;
an all-ones read is rejected before modification and as a readback result.
The complete active part normally takes about 201 ms and has no polling loop.

This mode changes only the two GPIO mux fields, their data bits and PMU PHY
isolation bit zero. It changes no clocks, regulators, PHY calibration or
controller state, reads no ELBI/DBI/config/BAR, and enables no link, DMA,
firmware or network service. Successful GPIO/register readback is not proof
that the chip booted firmware or established a PCIe link. This mode completed
on the phone in epoch 49: `power probe readback passed` and
`power probe restore verified`, followed by user-confirmed menu interaction.
The subsequent short epoch 50 contains only early boot; decode all retained
epochs to find the actual long test session.

## Controller status checkpoint

`b2l_wifi_diag=3` repeats the guarded
power probe and, only after successful power/reset/isolation readback and the
201 ms delay, reads six channel-zero ELBI registers. ELBI is mapped at
`0x13ed0000`, length 16 KiB, but remains unread if shared-state validation or
the power probe fails. Failure to map it stops before any register sampling.

| ELBI offset | Samsung driver name / purpose |
| --- | --- |
| `0x02c` | APP_LTSSM_ENABLE |
| `0x074` | ELBI_RDLH_LINKUP |
| `0x1d0` | SOFT_CORE_RESET |
| `0x288` | PCS global reset |
| `0x28c` | PHY PCS/PMA reset |
| `0x290` | MAC reset |

An all-ones value stops further controller reads. Power/isolation/pin
restoration runs after either success or a failed ELBI readback. This mode
writes no controller register and accesses no PHY, PCS, DBI, configuration
window, BAR or endpoint. No link training, IRQ, DMA, firmware or network
interface is enabled. Completion establishes only ELBI register accessibility
under the tested conditions. Mode 3 completed on the phone in epoch 51:
LTSSM enable was zero, link status `0xf15400`, and all four sampled reset
registers were one. The power restoration and interactive Home were verified.

## One Gen1 link attempt

`b2l_wifi_diag=4` follows the verified power and ELBI checkpoints. It accepts
only the observed inactive controller/reset
state and an unowned CLKREQ pad. It then uses the Exynos 9820 channel-zero
26 MHz PHY profile and DesignWare root-port link controls for one Gen1 x1
attempt. The first physical trial stopped during `phy-calibration`, before
root DBI setup or link training. PHY power-down, shared-state restoration and
interactive Home were verified. The diagnostic follow-up identified SYSREG
`0x13c11050`: baseline `0x1d02`, vendor write `0x1d0c`, readback `0x1d04`.
It also stopped before training, with verified restoration and interactive
Home. The stop line reports the number of link-status polls: zero means no
training status was sampled, so the initial `last_ELBI=0` is not a measured
link state.

Samsung's channel-zero calibration writes the same profile without verifying
its readback. The corrected trial preserves that write and accepts the exact
observed baseline/write/readback triple above as a board-specific exception.
Normal masked readback verification still applies otherwise; a different
baseline with the same discrepancy, any other missing bit or all-ones value
stops the probe. The exception is logged and does not apply to restoration
or any other register. That trial established a Gen1 x1 link on the phone,
followed by verified PHY shutdown, shared-state restoration and interactive
Home. The root DBI ID was `0xa598144d`; this is not the endpoint identity.
The physical meaning of bit 3 remains unconfirmed.

Additional I/O mappings, each 16 KiB, come from this board's device tree:

| Block | Base | Scope |
| --- | --- | --- |
| PHY | `0x13ef0000` | 48 common and 80 TRSV register words; power controls |
| PCS | `0x13ee0000` | Channel-zero reset, reference-clock and RX-idle controls |
| SYSREG_FSYS1 | `0x13c10000` | PCIe fields at `0x1044` and `0x1050` only |
| Root DBI | `0x13f00000` | Root link width/speed, auxiliary clock and PCI command controls |

The PHY data header records its pinned Samsung source hash. Independent
golden hashes in the host test check both arrays. Recovery's exposed kernel
configuration has no EXYNOS_OTP definition; this trial makes no OTP access.
CLKREQ uses the board's function 2 and pull-up 3, while the caller owns the
PERST output. Shared SYSREG and pin fields are restored with masked writes.
No CMU, ACPM DVFS or regulator setting is changed.

The sequence enables the PHY, pulses the documented resets, programs the
PHY/PCS profile, and configures the root port for one lane and target Gen1.
RX electrical-idle checking is bypassed while accessing DBI, as in Samsung's
accessor. Root bus mastering, SERR and parity responses are disabled; all
PCIe interrupts remain masked. PCI command/control writes put zero in W1C
status fields. Root vendor/device IDs are read for diagnostics, not rewritten;
an uninitialized zero root identity is allowed if control readback works.

Training has a 500 ms monotonic deadline and a second limit of 500 polls,
with 1 ms spacing. Preemption or an individual I/O access can extend observed
elapsed time. Only LTSSM states `0x0d..0x14` with negotiated speed 1 and width
1 count as success. There is one attempt, with no retry or panic on timeout.
No iATU/configuration window, endpoint BAR, SysMMU/DMA map or endpoint command
is touched; no firmware or network service is started.

On every path after initialization begins, the probe attempts to assert PERST,
disable LTSSM, mask interrupts, clear root bus mastering, request and check the
PHY power-down controls, and restore the shared pin/SYSREG and selected ELBI
fields. Then the caller restores isolation and WLAN power. Root DBI and PHY
configuration bytes are retained rather than restored to their S-Boot image;
the intended final condition is reset, isolated and powered down. Failed
quiescence is explicit and bounded, and does not suppress common restoration.
Look for all three results: `Gen1 link up`, `Gen1 quiesce verified`, and
`power probe restore verified`. Interactive Home alone does not prove a link.

## Read-only endpoint identity

`b2l_wifi_diag=5` repeats the verified
Gen1 sequence, then reads only CFG0 words at offsets `0x00`, `0x04`, `0x08`
and `0x2c` for bus 1/device 0/function 0. These contain vendor/device IDs,
command/status, PCI class/revision and subsystem IDs. This checkpoint completed
on the phone: `14e4:4475`, subsystem `14e4:4375`, PCI revision 5, class
`0x028000`, command zero, followed by verified CFG0/PHY/power cleanup and
interactive Home.

The live DT's configuration resource is `0x14ffe000`, length `0x2000`.
Samsung splits it into 4 KiB CFG0 and CFG1 halves and uses outbound viewport
1 for CFG0. Mode 5 maps a 16 KiB envelope at `0x14ffc000`, but accesses only
the four words at envelope offset `0x2000` plus the offsets above. It touches
neither the preceding memory aperture nor CFG1. Other modes do not map it.

After confirmed Gen1 x1 and RX-idle bypass, it verifies a type-1 root bridge
header and disabled root bus mastering, saves the viewport and root bus
numbers, selects outbound ATU1, and accepts only an inactive zero control
word. Unsupported/all-ones or occupied ATU state skips endpoint reads.
It temporarily sets primary/secondary/subordinate buses to 0/1/1, retaining
the latency byte, and programs only ATU1's CFG0 descriptor:

| Field | Value |
| --- | --- |
| CPU base / limit | `0x14ffe000` / `0x14ffefff` |
| PCI target | `0x01000000` (01:00.0) |
| Type / enable | `4` (CFG0) / `0x80000000` |

Descriptor words are written in full while disabled and read back exactly;
old all-ones address/limit contents are data rather than an RMW prerequisite.
All descriptor fields are checked before one enable write, followed by at
most five 9 ms enable checks. After a fixed 100 ms readiness interval, the
four reads share a 100 ms deadline, with no endpoint request retries. Before
each word, the probe checks the link, negotiated Gen1 x1, root command and
ATU enable. A single MMIO access can still fault or exceed the software
deadline; host tests do not prove hardware accessibility.

An invalid/unexpected vendor/device ID, enabled endpoint I/O/memory/master
command bits, invalid word or mismatched subsystem stops further reads.
Success requires `14e4:4475` and subsystem `14e4:4375`; the PCI revision is
logged separately and is not a backplane chip revision or firmware selection.
The probe writes no endpoint register, BAR or command, enables no interrupt,
programs no memory/inbound ATU region, and allocates no DMA map or firmware.

On exit it disables its owned ATU1 region with checked bounded retries and
restores root bus numbers and viewport. The disabled descriptor's programming
bytes are retained. Cleanup failure is explicit, contributes to the Gen1
quiescence failure result, and does not suppress the common PHY/power cleanup.
Require `endpoint identity verified`, `endpoint probe end: stage=complete
cleanup=verified`, `Gen1 quiesce verified` and `power probe restore verified`.

## Internal chip identity

The userspace loader now selects `b2l_wifi_diag=6`. After the verified endpoint
identity it temporarily assigns the first BAR0 aperture and Broadcom's
`PCI_BAR0_WIN` to read three chipcommon words: chip ID at `0x00`, capabilities
at `0x04` and the EROM pointer at `0xfc`. Its hardware outcome is pending.
There are no chip register writes, RAM mappings, core resets, firmware loads,
interrupts or DMA clients in this checkpoint.

Recovery's cached BAR0 is a 64 KiB, non-prefetchable 64-bit aperture at
`0x14400000`; the separate 4 MiB RAM aperture is not used. Mode 6 maps a
16 KiB envelope at `0x14400000`, but programs outbound ATU0 for only the first
4 KiB, with CPU and PCI base `0x14400000` and limit `0x14400fff`. ATU0 must
initially have zero control. Other active or invalid ATU0 state skips the
probe. Mode 5 still programs no memory translation or endpoint register.

The probe saves endpoint command, BAR0 low/high and vendor window. It accepts
only I/O/memory/master command bits zero, high BAR0 zero, and low BAR0 either
`4` (unassigned 64-bit memory) or `0x14400004` (the measured recovery address).
It does not write a sizing pattern or access BAR2. With memory decoding still
off it programs/checks BAR0 and PCI configuration offset `0x80` to
`0x18000000`, the pinned Broadcom enumeration base. It then enables endpoint
memory decoding only, preserving other command bits and writing zero to
status W1C bits. Endpoint and root bus mastering remain disabled.

The three reads share a 100 ms deadline. Before each, the probe verifies
the memory route, CFG0 prerequisites, Gen1 x1, root command, endpoint command,
BAR0 and vendor window. A bad chip ID or all-ones word stops further reads.
Success requires chip ID `0x4375`; revision/package/interconnect fields are
decoded using Broadcom's `CID_*` masks. The EROM pointer is logged but never
followed. Neither the PCI revision nor the internal chip revision alone
selects the board's NVRAM variant.

Cleanup first disables endpoint memory decoding with checked bounded retries.
Only after that succeeds does it restore the saved window and BAR0 words.
It disables its owned ATU0 and returns viewport selection to CFG0, then mode 5
performs its normal CFG0/bus/viewport cleanup. If link prerequisites fail, no
further endpoint request is issued. Inaccessible or failed restoration is
explicit, contributes to the overall quiescence failure result, and still
permits PERST assertion and common PHY/power shutdown. Descriptor contents
remain programmed while disabled. A successful chip read and successful
cleanup are separate results.

## Recovery evidence

With one rooted beyond2lte in TWRP, collect cached PCI IDs, resources, driver
bindings, platform status and the exported WLAN_REG_ON GPIO:

```sh
rtk proxy python3 scripts/probe-b2l-wifi.py --output /existing/private/parent/new-capture
```

Use `--serial` to select a particular recovery if multiple devices are
connected. Output directories are exclusive and mode 0700; files are 0600.
The collector does not mount filesystems, read MAC addresses or saved networks,
read live PCI configuration space, change GPIOs, or invoke `pcie_sysfs` tests.
An absent PCI endpoint may mean the link is off. Recovery's `devmem` executable
cannot provide a baseline here because this recovery has no `/dev/mem`; no
device node was created to bypass that limitation.

Original Wi-Fi station firmware, CLM and nine candidate NVRAM files have been
extracted privately from the verified original vendor backup. They are not
repository or CI inputs. Selecting the correct module/board NVRAM remains
open; no random variant is used.

## Following checkpoints

1. Validate internal chip identity and BAR0/ATU/PHY/power cleanup, preserving
   the validated endpoint-identity BOOT as rollback.
2. Enumerate the required internal cores, select verified board firmware/NVRAM,
   and bring up firmware with an appropriate DMA/SysMMU design.
3. Establish scanning, authentication, packet transport and DHCP, then adapt
   the HakiOS network and Apple80211 interfaces to this iOS release.

Linux can initialize this hardware, but its driver is not a loadable XNU
driver. The S20 Ultra reference uses Exynos 990; its MMIO/HVC/PHY/DMA settings
cannot be copied to Exynos 9820. HakiOS's chip driver is Qualcomm/ath11k;
only its network and iOS integration are candidates for reuse here.

## Validation

`rtk proxy python3 tests/test_wifi_diagnostics.py` runs the actual diagnostic
control flow under ASan/UBSan, with an MMIO allowlist, unsupported boot modes,
mapping failures at every position, reverse cleanup, pin decoding, an invalid
register and unchanged simulated memory in mode 1. Mode 2 tests preserve
unrelated pin/PMU bits, drop every write in turn, reject all-ones readback,
exercise unexpected baseline states and bound persistent restoration failure.
Mode 3 additionally checks the exact ELBI read allowlist and requires asserted
reset, power/bypass readback and the delay before every controller read. It
tests all-ones controller words, rejected power/clock state and failed mapping
with cleanup, and permits no controller writes. Recovery tests exercise wrong-device
and ambiguous-device rejection, PCI parsing, private output and no overwrite.
These host checks cannot prove hardware register accessibility or Wi-Fi support.

`rtk proxy python3 tests/test_wifi_gen1.py` runs the actual mode-4 control flow
with strict MMIO, power/reset and DBI RX-idle prerequisites. It checks the
source PHY table hashes, Gen1 success, timeout, preemption/deadline behavior,
unexpected speed, invalid DBI data, inactive-state rejection, every mapping
failure and a dropped write at every position. Permanent LTSSM/PHY cleanup
failures remain explicit while common power restoration is still attempted.
The measured SYSREG readback is replayed with the exact vendor write, including
dropped writes throughout that path and rejection of a different baseline,
another missing bit and invalid readback.
The mode-4 backend rejects bus-master/IRQ enabling, W1C status acknowledgement,
CMU writes, and all ATU/endpoint/config/BAR access. Mode 5 additionally verifies
the exact ATU1 CFG0 mapping and four ordered reads, checks readiness and the
deadline, and exercises all ten mapping failures and every dropped write.
It rejects wrong/all-ones identities, endpoint mastering, link loss, root
command/speed changes, a non-bridge header, occupied/unsupported ATU state and
failed enable. Permanent ATU-disable failure remains explicit while common
power restoration still runs. Prior viewport selection and root bus numbers
are restored, including a previously selected inbound viewport. No endpoint
writes, memory/inbound region programming or BAR access is permitted.

Mode 6 tests the exact first-page memory translation, three ordered chip reads,
64-bit BAR0/window setup, W1C-safe memory-only command and restoration. It
exercises all eleven mapping failures, every dropped write, wrong/all-ones
chip words, deadline expiry, unexpected BAR/window state, occupied ATU0 and
failed enable. Permanent command/window/ATU0 cleanup failures and link loss
remain explicit while common power restoration still runs. The backend rejects
endpoint bus mastering, BAR2/RAM access and every chip-register write.

## Source references

Samsung/LineageOS is pinned to
`a412cfaf86b980ce35cae96a35f678c8ea551575`:

- [beyond2lte configuration](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/arch/arm64/configs/exynos9820-beyond2lte_defconfig)
- [PCIe host driver and sequencing](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/pci/dwc/pcie-exynos-host-v0.c)
- [PCIe register offsets](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/pci/dwc/pcie-exynos-host-v0.h)
- [Exynos 9820 PHY calibration](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/pci/dwc/pci-exynos9820_cal.c)
- [DesignWare root-port link setup](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/pci/dwc/pcie-designware.c)
- [DesignWare root configuration semantics](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/pci/dwc/pcie-designware-host.c)
- [GPIO bank offsets](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/pinctrl/samsung/pinctrl-exynos-arm64.c)
- [Broadcom BAR0 window definitions](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/net/wireless/broadcom/bcmdhd_101_16/include/pcicfg.h)
- [Broadcom enumeration base](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/net/wireless/broadcom/bcmdhd_101_16/include/hndsoc.h)
- [Chipcommon layout and identity masks](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/net/wireless/broadcom/bcmdhd_101_16/include/sbchipc.h)
- [Broadcom chip attachment and identity decoding](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/net/wireless/broadcom/bcmdhd_101_16/siutils.c)
- [Broadcom PCIe chip-ID reader](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/net/wireless/broadcom/bcmdhd_101_16/dhd_pcie.c)
- [Clock register bases, offsets and fields](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/soc/samsung/cal-if/exynos9820/cmucal-sfr.c)
- [WLAN power and PCIe channel setup](https://github.com/LineageOS/android_kernel_samsung_exynos9820/blob/a412cfaf86b980ce35cae96a35f678c8ea551575/drivers/net/wireless/broadcom/bcmdhd_101_16/dhd_custom_exynos.c)

Reusable integration references:

- [HakiOS XNU packet interface](https://github.com/oosexgang/hakios-xnu-kernel/blob/63fc2b4633bac3af8e57dadab9f5a8d4cb940438/drivers/net/hakios.net.c)
- [HakiOS Wi-Fi service](https://github.com/oosexgang/hakios-xnu-kernel/blob/63fc2b4633bac3af8e57dadab9f5a8d4cb940438/drivers/wifi/hakios.wlan.cpp)
- [BCM4375 on Exynos 990 bring-up report](https://github.com/Bentlybro/z3s-mainline-linux/blob/main/docs/WIFI_BRINGUP.md)
