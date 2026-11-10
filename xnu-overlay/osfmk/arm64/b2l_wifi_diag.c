/* SPDX-License-Identifier: BSD-2-Clause
 * First Wi-Fi bring-up checkpoint for beyond2lte / Exynos 9820.
 *
 * b2l_wifi_diag=1 samples shared PMU, GPIO and CMU registers once, read only.
 * b2l_wifi_diag=2 additionally pulses WLAN power with PERST held low, tests
 * PHY isolation bypass readback, then restores the owned bits.
 * b2l_wifi_diag=3 additionally reads six controller ELBI status/reset words
 * during that pulse. It writes no controller register, trains no link and
 * accesses no PHY/PCS/DBI/config/BAR, firmware or network registration.
 * b2l_wifi_diag=4 initializes the channel-zero PHY/root port for one bounded
 * Gen1 x1 link attempt, then asserts reset and powers the PHY down. No ATU,
 * endpoint configuration/BAR, DMA mapping, IRQ enabling or firmware loading.
 * b2l_wifi_diag=5 additionally reads four endpoint configuration words through
 * a temporary outbound CFG0 region, then disables it. No endpoint writes.
 * b2l_wifi_diag=6 additionally sets a temporary BAR0/window and memory-only
 * endpoint command for three chipcommon reads. Never enables bus mastering,
 * maps dongle RAM, writes chip registers or loads firmware.
 * A powered PHY alone does not establish that DBI/ELBI accesses are safe.
 * All addresses/offsets are sourced in docs/wifi-bringup.md.
 */
#include <arm64/b2l_early.h>
#include <arm64/b2l_wifi_phy_data.h>
#include <kern/clock.h>
#include <kern/misc_protos.h>
#include <mach/mach_time.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <vm/pmap.h>

#define wlog(...) b2l_early_trace("B2L WIFI: " __VA_ARGS__)

struct wifi_region {
    vm_offset_t physical, mapped;
    vm_size_t size;
};

static uint32_t
wifi_read(const struct wifi_region *region, unsigned offset)
{
    return *(volatile const uint32_t *)(region->mapped + offset);
}

static void
wifi_write(const struct wifi_region *region, unsigned offset, uint32_t value)
{
    *(volatile uint32_t *)(region->mapped + offset) = value;
    __asm__ volatile ("dsb sy" ::: "memory");
}

/* Change and restore only owned bits, preserving every other pin and PMU bit.
 * An all-ones register is not used as the input to a read-modify-write. */
static int
wifi_bits(const struct wifi_region *region, unsigned offset, uint32_t mask, uint32_t value)
{
    uint32_t before = wifi_read(region, offset);
    if (before == UINT32_MAX) {
        wlog("bits invalid read pa=%#lx off=%#x mask=%#x\n",
            (unsigned long)region->physical, offset, mask);
        return -1;
    }
    uint32_t after = (before & ~mask) | (value & mask);
    if (after != before) wifi_write(region, offset, after);
    uint32_t checked = wifi_read(region, offset);
    if (checked != UINT32_MAX && (checked & mask) == (value & mask)) return 0;
    wlog("bits mismatch pa=%#lx off=%#x mask=%#x before=%#x got=%#x want=%#x\n",
        (unsigned long)region->physical, offset, mask, before, checked, value & mask);
    return -1;
}

static int
wifi_restore_bits(const struct wifi_region *region, unsigned offset, uint32_t mask, uint32_t value)
{
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        if (!wifi_bits(region, offset, mask, value)) return 0;
        delay_for_interval(1, NSEC_PER_MSEC);
    }
    return -1;
}

/* Samsung writes this channel-zero profile without checking its readback.
 * Epoch 53 measured 0x1d02 -> write 0x1d0c -> read 0x1d04 on this board.
 * Preserve that exact vendor write; accept only the exact observed exception,
 * not a general waiver for bit 3 or a claim that the bit is read-only. */
static int
wifi_phy_sysreg_profile(const struct wifi_region *sysreg)
{
    uint32_t before = wifi_read(sysreg, 0x1050);
    if (before == UINT32_MAX) {
        wlog("PHY SYSREG profile invalid initial read\n");
        return -1;
    }
    uint32_t next = (before & ~0xfeu) | 0x0cu;
    if (next != before) wifi_write(sysreg, 0x1050, next);
    uint32_t checked = wifi_read(sysreg, 0x1050);
    if (checked != UINT32_MAX && (checked & 0xfeu) == 0x0c) return 0;
    if (before == 0x1d02 && next == 0x1d0c && checked == 0x1d04) {
        wlog("PHY SYSREG profile: observed board readback before=%#x wrote=%#x got=%#x\n",
            before, next, checked);
        return 0;
    }
    wlog("PHY SYSREG profile mismatch before=%#x wrote=%#x got=%#x mask=0xfe want=0xc\n",
        before, next, checked);
    return -1;
}

/* PCI configuration control is in the low half-word. Write zero to status
 * bits in the high half, and to PME_Status (W1C) in the PMCSR low half. */
static int
wifi_control16(const struct wifi_region *dbi, unsigned off, uint32_t mask, uint32_t value)
{
    uint32_t before = wifi_read(dbi, off);
    if (before == UINT32_MAX) return -1;
    uint32_t next = ((before & 0xffffu) & ~mask) | (value & mask);
    if (off == 0x44) next &= ~0x8000u;
    wifi_write(dbi, off, next);
    uint32_t checked = wifi_read(dbi, off);
    if (checked != UINT32_MAX && (checked & mask) == (value & mask)) return 0;
    wlog("PCI control mismatch off=%#x mask=%#x before=%#x got=%#x want=%#x\n",
        off, mask, before, checked, value & mask);
    return -1;
}

static int
wifi_reset_pulse(const struct wifi_region *elbi, unsigned off, unsigned final_us)
{
    wifi_write(elbi, off, 1); delay(10);
    wifi_write(elbi, off, 0); delay(10);
    wifi_write(elbi, off, 1); delay(final_us);
    uint32_t value = wifi_read(elbi, off);
    if (value == 1) return 0;
    wlog("reset pulse mismatch off=%#x got=%#x want=1\n", off, value);
    return -1;
}

static int
wifi_atu_enable(const struct wifi_region *dbi, unsigned index)
{
    uint32_t control = 0;
    wifi_write(dbi, 0x908, 0x80000000);
    for (unsigned attempt = 0; attempt < 5; attempt++) {
        control = wifi_read(dbi, 0x908);
        if (control == 0x80000000) return 0;
        if (control == UINT32_MAX) break;
        delay_for_interval(9, NSEC_PER_MSEC);
    }
    wlog("ATU%u enable failed: readback=%#x\n", index, control);
    return -1;
}

static int
wifi_cfg_ready(struct wifi_region *regions, uint64_t deadline)
{
    const struct wifi_region *elbi = &regions[4], *dbi = &regions[8];
    uint32_t link = wifi_read(elbi, 0x74), status = wifi_read(dbi, 0x80);
    uint32_t command = wifi_read(dbi, 0x04), viewport = wifi_read(dbi, 0x900);
    if (mach_absolute_time() >= deadline || link == UINT32_MAX ||
        (link & 31u) < 0x0d || (link & 31u) > 0x14 || status == UINT32_MAX ||
        ((status >> 16) & 15u) != 1 || ((status >> 20) & 63u) != 1 ||
        command == UINT32_MAX || (command & 0x147u) != 2 || viewport != 1) return 0;
    return wifi_read(dbi, 0x908) == 0x80000000;
}

static int
wifi_cfg_write_checked(struct wifi_region *regions, unsigned offset, uint32_t value,
    uint64_t deadline)
{
    if (!wifi_cfg_ready(regions, deadline)) return -1;
    const struct wifi_region *cfg = &regions[9];
    wifi_write(cfg, 0x2000 + offset, value);
    if (!wifi_cfg_ready(regions, deadline)) return -1;
    uint32_t checked = wifi_read(cfg, 0x2000 + offset);
    if (checked == value) return 0;
    wlog("BAR0 config mismatch off=%#x got=%#x want=%#x\n", offset, checked, value);
    return -1;
}

static int
wifi_ep_memory_command(struct wifi_region *regions, uint32_t value, uint64_t deadline)
{
    if (!wifi_cfg_ready(regions, deadline)) return -1;
    const struct wifi_region *cfg = &regions[9];
    uint32_t before = wifi_read(cfg, 0x2004);
    if (before == UINT32_MAX || (value != 0 && value != 2)) return -1;
    wifi_write(cfg, 0x2004, ((before & 0xffffu) & ~7u) | value);
    if (!wifi_cfg_ready(regions, deadline)) return -1;
    uint32_t checked = wifi_read(cfg, 0x2004);
    if (checked != UINT32_MAX && (checked & 7u) == value) return 0;
    wlog("BAR0 memory command mismatch got=%#x want=%#x; BME never requested\n", checked, value);
    return -1;
}

static int
wifi_cfg_restore(struct wifi_region *regions, unsigned offset, uint32_t value)
{
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        if (!wifi_cfg_write_checked(regions, offset, value, UINT64_MAX)) return 0;
        delay_for_interval(1, NSEC_PER_MSEC);
    }
    return -1;
}

static int
wifi_chipcommon_probe(struct wifi_region *regions)
{
    const struct wifi_region *dbi = &regions[8], *cfg = &regions[9], *bar = &regions[10];
    static const struct { unsigned off; uint32_t value; } descriptor[] = {
        { 0x90c, 0x14400000 }, { 0x910, 0 }, { 0x914, 0x14400fff },
        { 0x918, 0x14400000 }, { 0x91c, 0 }, { 0x904, 0 },
    };
    static const unsigned offsets[] = { 0, 4, 0xfc };
    uint32_t words[3] = { 0 }, low = 0, high = 0, window = 0, command = 0;
    int atu_owned = 0, ep_changed = 0, cleanup_failed = 0, cfg_selected = 0;
    const char *stage = "initial-state";
    uint64_t deadline;
    clock_interval_to_deadline(100, NSEC_PER_MSEC, &deadline);
    if (!wifi_cfg_ready(regions, deadline)) {
        wlog("chipcommon probe skipped: configuration prerequisites\n");
        return 0;
    }
    /* Cached recovery resources establish BAR0 as a 64 KiB 64-bit aperture at
     * 0x14400000. Do not size-probe BARs or touch BAR2's dongle RAM aperture. */
    static const unsigned config_offsets[] = { 0x04, 0x10, 0x14, 0x80 };
    uint32_t saved[4];
    for (unsigned i = 0; i < sizeof(config_offsets) / sizeof(config_offsets[0]); i++) {
        if (!wifi_cfg_ready(regions, deadline)) {
            wlog("chipcommon probe skipped before config +%#x: prerequisites\n", config_offsets[i]);
            return 0;
        }
        saved[i] = wifi_read(cfg, 0x2000 + config_offsets[i]);
    }
    command = saved[0]; low = saved[1]; high = saved[2]; window = saved[3];
    if (command == UINT32_MAX || (command & 7u) || high != 0 ||
        (low != 4 && low != 0x14400004) || window == UINT32_MAX) {
        wlog("chipcommon probe skipped: command=%#x BAR0=%#x:%#x window=%#x\n",
            command, high, low, window);
        return 0;
    }
    wlog("chipcommon probe begin: BAR0 first 4 KiB only; no chip writes, RAM, DMA or firmware\n");
    if (wifi_bits(dbi, 0x900, UINT32_MAX, 0)) goto out;
    uint32_t control = wifi_read(dbi, 0x908);
    if (control != 0) {
        wlog("chipcommon probe skipped: outbound ATU0 control=%#x is not inactive zero\n", control);
        goto out;
    }
    atu_owned = 1;
    stage = "bar0-route";
    for (unsigned i = 0; i < sizeof(descriptor) / sizeof(descriptor[0]); i++) {
        wifi_write(dbi, descriptor[i].off, descriptor[i].value);
        if (wifi_read(dbi, descriptor[i].off) != descriptor[i].value) goto out;
    }
    if (wifi_atu_enable(dbi, 0) ||
        wifi_bits(dbi, 0x900, UINT32_MAX, 1)) goto out;
    stage = "bar0-config";
    ep_changed = 1;
    if (wifi_cfg_write_checked(regions, 0x14, 0, deadline) ||
        wifi_cfg_write_checked(regions, 0x10, 0x14400004, deadline) ||
        wifi_cfg_write_checked(regions, 0x80, 0x18000000, deadline) ||
        wifi_ep_memory_command(regions, 2, deadline)) goto out;
    stage = "chipcommon-reads";
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        if (wifi_bits(dbi, 0x900, UINT32_MAX, 0)) goto out;
        control = wifi_read(dbi, 0x908);
        if (wifi_bits(dbi, 0x900, UINT32_MAX, 1) || control != 0x80000000 ||
            !wifi_cfg_ready(regions, deadline) ||
            (wifi_read(cfg, 0x2004) & 7u) != 2 ||
            wifi_read(cfg, 0x2010) != 0x14400004 || wifi_read(cfg, 0x2014) != 0 ||
            wifi_read(cfg, 0x2080) != 0x18000000) goto out;
        words[i] = wifi_read(bar, offsets[i]);
        wlog("chipcommon +%#x raw=%#x\n", offsets[i], words[i]);
        if (words[i] == UINT32_MAX || (i == 0 && (words[i] & 0xffffu) != 0x4375)) goto out;
    }
    wlog("chipcommon identity verified: chip=%#x revision=%u package=%u interconnect=%u; EROM=%#x not followed\n",
        words[0] & 0xffffu, (words[0] >> 16) & 15u, (words[0] >> 20) & 15u,
        words[0] >> 28, words[2]);
    stage = "complete";
out:
    /* Disable memory decoding before restoring BARs. PCI status W1C bits are
     * written as zero; bus mastering was never enabled. If the link is lost,
     * do not issue more config requests; caller still asserts PERST/power off. */
    cfg_selected = !wifi_restore_bits(dbi, 0x900, UINT32_MAX, 1);
    if (!cfg_selected) cleanup_failed = -1;
    if (ep_changed) {
        int disabled = 0;
        for (unsigned attempt = 0; cfg_selected && attempt < 3; attempt++) {
            if (!wifi_ep_memory_command(regions, 0, UINT64_MAX)) {
                disabled = 1; break;
            }
            delay_for_interval(1, NSEC_PER_MSEC);
        }
        if (!disabled) cleanup_failed = -1;
        else {
            cleanup_failed |= wifi_cfg_restore(regions, 0x80, window);
            cleanup_failed |= wifi_cfg_restore(regions, 0x14, high);
            cleanup_failed |= wifi_cfg_restore(regions, 0x10, low);
        }
    }
    if (atu_owned) {
        if (wifi_restore_bits(dbi, 0x900, UINT32_MAX, 0)) cleanup_failed = -1;
        else cleanup_failed |= wifi_restore_bits(dbi, 0x908, UINT32_MAX, 0);
    }
    cleanup_failed |= wifi_restore_bits(dbi, 0x900, UINT32_MAX, 1);
    wlog("chipcommon probe end: stage=%s cleanup=%s; BAR0 decoding and owned ATU0 disable requested\n",
        stage, cleanup_failed ? "FAILED" : "verified");
    return cleanup_failed;
}

/* Samsung uses outbound viewport 1 for CFG0, bus 1/device 0/function 0.
 * The live DT's 0x14ffe000/0x2000 config resource is split into two 4 KiB
 * CFG0/CFG1 halves. Map a 16 KiB aligned envelope but read only four words
 * in CFG0. Never map a BAR, program a memory/inbound region or write the EP. */
static int
wifi_endpoint_identity(struct wifi_region *regions, uint32_t mode)
{
    const struct wifi_region *elbi = &regions[4], *dbi = &regions[8], *cfg = &regions[9];
    static const unsigned offsets[] = { 0x00, 0x04, 0x08, 0x2c };
    static const struct { unsigned off; uint32_t value; } descriptor[] = {
        { 0x90c, 0x14ffe000 }, { 0x910, 0 }, { 0x914, 0x14ffefff },
        { 0x918, 0x01000000 }, { 0x91c, 0 }, { 0x904, 4 },
    };
    uint32_t words[4] = { 0 }, viewport = wifi_read(dbi, 0x900);
    uint32_t buses = wifi_read(dbi, 0x18);
    uint32_t header = wifi_read(dbi, 0x0c), initial_command = wifi_read(dbi, 0x04);
    int viewport_changed = 0, buses_changed = 0, atu_owned = 0, cleanup_failed = 0;
    const char *stage = "initial-state";
    if (viewport == UINT32_MAX || buses == UINT32_MAX || header == UINT32_MAX ||
        ((header >> 16) & 0x7fu) != 1 || initial_command == UINT32_MAX ||
        (initial_command & 0x147u) != 2) {
        wlog("endpoint probe skipped: invalid viewport/bus/header/root-command state\n");
        return 0;
    }
    wlog("endpoint probe begin: CFG0 01:00.0, four read-only words; root BME stays off\n");
    viewport_changed = 1;
    if (wifi_bits(dbi, 0x900, UINT32_MAX, 1)) goto out;
    uint32_t control = wifi_read(dbi, 0x908);
    if (control == UINT32_MAX || control != 0) {
        wlog("endpoint probe skipped: outbound ATU1 control=%#x is not inactive zero\n", control);
        goto out;
    }
    atu_owned = 1;
    buses_changed = 1;
    stage = "cfg0-programming";
    if (wifi_bits(dbi, 0x18, 0xffffff, 0x010100)) goto out;
    /* Own all descriptor bits while disabled. Like Samsung, write full words;
     * an old address/limit of all ones is data, not a failed RMW prerequisite.
     * Every requested new word is non-all-ones and must read back exactly. */
    for (unsigned i = 0; i < sizeof(descriptor) / sizeof(descriptor[0]); i++) {
        wifi_write(dbi, descriptor[i].off, descriptor[i].value);
        uint32_t checked = wifi_read(dbi, descriptor[i].off);
        if (checked != descriptor[i].value) {
            wlog("endpoint ATU1 mismatch off=%#x got=%#x want=%#x\n",
                descriptor[i].off, checked, descriptor[i].value);
            goto out;
        }
    }
    /* DesignWare enable readback: one write and at most five 9 ms waits. */
    if (wifi_atu_enable(dbi, 1)) goto out;
    /* Conservative fixed readiness interval; no retry of endpoint requests. */
    delay_for_interval(100, NSEC_PER_MSEC);
    uint64_t deadline;
    clock_interval_to_deadline(100, NSEC_PER_MSEC, &deadline);
    stage = "identity-reads";
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        uint32_t link = wifi_read(elbi, 0x74), status = wifi_read(dbi, 0x80);
        uint32_t command = wifi_read(dbi, 0x04), atu = wifi_read(dbi, 0x908);
        if (mach_absolute_time() >= deadline || link == UINT32_MAX ||
            (link & 31u) < 0x0d || (link & 31u) > 0x14 || status == UINT32_MAX ||
            ((status >> 16) & 15u) != 1 || ((status >> 20) & 63u) != 1 ||
            command == UINT32_MAX || (command & 0x147u) != 2 || atu != 0x80000000) {
            wlog("endpoint probe stopped before +%#x: link/root/ATU/deadline guard\n", offsets[i]);
            goto out;
        }
        words[i] = wifi_read(cfg, 0x2000 + offsets[i]);
        wlog("endpoint CFG0 +%#x raw=%#x\n", offsets[i], words[i]);
        if (words[i] == UINT32_MAX || (i == 0 && words[i] != 0x447514e4) ||
            (i == 1 && (words[i] & 7u)) || (i == 3 && words[i] != 0x437514e4)) {
            wlog("endpoint probe stopped: unexpected identity/command at +%#x\n", offsets[i]);
            goto out;
        }
    }
    wlog("endpoint identity verified: 14e4:4475 subsystem 14e4:4375 PCI revision=%u class=%#x; no BAR/DMA/firmware\n",
        words[2] & 255u, words[2] >> 8);
    stage = "complete";
    if (mode == 6) cleanup_failed |= wifi_chipcommon_probe(regions);
out:
    /* Leave our outbound descriptor disabled, retaining its programming bytes.
     * Restore root bus numbers and viewport selection before PHY shutdown. */
    if (atu_owned) {
        if (wifi_restore_bits(dbi, 0x900, UINT32_MAX, 1)) cleanup_failed = -1;
        else cleanup_failed |= wifi_restore_bits(dbi, 0x908, UINT32_MAX, 0);
    }
    if (buses_changed) cleanup_failed |= wifi_restore_bits(dbi, 0x18, 0xffffff, buses);
    if (viewport_changed) cleanup_failed |= wifi_restore_bits(dbi, 0x900, UINT32_MAX, viewport);
    wlog("endpoint probe end: stage=%s cleanup=%s; owned CFG0 disable requested; no firmware/networking\n",
        stage, cleanup_failed ? "FAILED" : "verified");
    return cleanup_failed;
}

static void
wifi_gen1_probe(struct wifi_region *regions, uint32_t mode)
{
    const struct wifi_region *gpio = &regions[2], *elbi = &regions[4];
    const struct wifi_region *phy = &regions[5], *pcs = &regions[6];
    const struct wifi_region *sysreg = &regions[7], *dbi = &regions[8];
    struct { unsigned off; uint32_t mask, value; } saved[] = {
        { 0x18, 2, 0 }, { 0xf4, 0x11, 0 }, { 0x1b8, 3, 0 }, { 0x2c8, 0xfff, 0 },
    };
    uint32_t clock_mux, clock_pull, hs, lane, idle;
    uint32_t ro_before = 0, link = 0, status = 0;
    int ro_changed = 0, dbi_ready = 0, trained = 0, cleanup_failed = 0;
    unsigned polls = 0;
    const char *stage = "pins-and-power";
    /* Accept the inactive controller/reset state verified in epoch 51. */
    if (wifi_read(elbi, 0x2c) != 0 || (wifi_read(elbi, 0x74) & 31u) != 0 ||
        wifi_read(elbi, 0x1d0) != 1 || wifi_read(elbi, 0x288) != 1 ||
        wifi_read(elbi, 0x28c) != 1 || wifi_read(elbi, 0x290) != 1) {
        wlog("Gen1 probe skipped: controller differs from verified idle baseline\n");
        return;
    }
    clock_mux = wifi_read(gpio, 0x20); clock_pull = wifi_read(gpio, 0x28);
    if (clock_mux == UINT32_MAX || clock_pull == UINT32_MAX || (clock_mux & 15u) != 0) {
        wlog("Gen1 probe skipped: CLKREQ pad differs from verified idle baseline\n");
        return;
    }
    hs = wifi_read(sysreg, 0x1044); lane = wifi_read(sysreg, 0x1050);
    idle = wifi_read(pcs, 0xec);
    if (hs == UINT32_MAX || lane == UINT32_MAX || idle == UINT32_MAX) {
        wlog("Gen1 probe skipped: controller/shared state differs from verified idle baseline\n");
        return;
    }
    for (unsigned i = 0; i < sizeof(saved) / sizeof(saved[0]); i++) {
        saved[i].value = wifi_read(elbi, saved[i].off);
        if (saved[i].value == UINT32_MAX) {
            wlog("Gen1 probe skipped: invalid ELBI control word\n");
            return;
        }
    }
    wlog("Gen1 probe begin: channel 0, 26 MHz PHY profile, x1; one 500 ms attempt\n");
    /* Keep all PCIe interrupt sources masked. There is no IRQ handler or DMA
     * client in this experiment. Do not restore an old interrupt-enable mask. */
    if (wifi_bits(elbi, 0x0c, UINT32_MAX, 0) || wifi_bits(elbi, 0x10, UINT32_MAX, 0) ||
        wifi_bits(elbi, 0x14, UINT32_MAX, 0) ||
        wifi_bits(gpio, 0x28, 15u, 3u) || wifi_bits(gpio, 0x20, 15u, 2u) ||
        wifi_bits(pcs, 0x100, 1u << 6, 0) || wifi_bits(pcs, 0x104, 1u << 7, 0))
        goto out;
    wifi_write(phy, 0x80, 0xc0); wifi_write(phy, 0x15c, 0x7e);
    if (wifi_bits(pcs, 0xec, 8u, 8u)) goto out; /* Ignore RX electrical idle for DBI access. */
    wifi_write(elbi, 0x1d0, 0); delay(20);
    if (wifi_bits(elbi, 0x1d0, 1, 1) || wifi_bits(gpio, 0x24, 4, 4)) goto out;
    delay_for_interval(20, NSEC_PER_MSEC);
    stage = "phy-calibration";
    if (wifi_bits(elbi, 0xf4, 0x11, 0x11) || wifi_bits(elbi, 0x1b8, 3, 2) ||
        wifi_bits(elbi, 0x2c8, 0xfff, 0) || wifi_bits(sysreg, 0x1044, 2, 2) ||
        wifi_phy_sysreg_profile(sysreg) ||
        wifi_bits(sysreg, 0x1050, 0x1000, 0x1000) || wifi_reset_pulse(elbi, 0x288, 10))
        goto out;
    for (unsigned i = 0; i < sizeof(b2l_wifi_cmn); i++) wifi_write(phy, i * 4, b2l_wifi_cmn[i]);
    for (unsigned i = 0; i < sizeof(b2l_wifi_trsv); i++) wifi_write(phy, 0xc0 + i * 4, b2l_wifi_trsv[i]);
    wifi_write(pcs, 0xf8, 0x70); wifi_write(pcs, 0x100, 0x87); wifi_write(pcs, 0x104, 0x50);
    if (wifi_bits(pcs, 0x0c, 0x12, 0x10) || wifi_reset_pulse(elbi, 0x290, 10) ||
        wifi_reset_pulse(elbi, 0x28c, 100)) goto out;
    uint32_t cdr = wifi_read(pcs, 0xd0);
    if (cdr == UINT32_MAX) { wlog("Gen1 CDR initial read invalid\n"); goto out; }
    wifi_write(pcs, 0xd0, cdr | 0xc0); delay(20);
    cdr = wifi_read(pcs, 0xd0);
    if (cdr == UINT32_MAX) { wlog("Gen1 CDR pulse read invalid\n"); goto out; }
    wifi_write(pcs, 0xd0, (cdr & ~0xc0u) | 0x80); wifi_write(pcs, 0xd0, cdr & ~0xc0u);
    if (wifi_bits(elbi, 0x18, 2, 0)) goto out; /* Enable bus-number handling; no ATU. */
    stage = "root-dbi";
    uint32_t root_id = wifi_read(dbi, 0);
    ro_before = wifi_read(dbi, 0x8bc);
    /* Samsung programs the root vendor/device IDs during full PCI bus setup;
     * zero can be an uninitialized root identity, not an absent endpoint. */
    if (root_id == UINT32_MAX || ro_before == UINT32_MAX) {
        wlog("Gen1 probe stopped: invalid root DBI identity/control\n");
        goto out;
    }
    wlog("Gen1 root DBI ID=%#x; endpoint remains unconfigured\n", root_id);
    dbi_ready = 1;
    stage = "root-policy";
    /* Root command: memory decoding only, never bus mastering. Status W1C
     * fields are written as zero. No endpoint configuration window is mapped. */
    if (wifi_control16(dbi, 0x04, 0x147, 2) || wifi_control16(dbi, 0x44, 0x103, 0)) goto out;
    ro_changed = 1;
    if (wifi_bits(dbi, 0x8bc, 1, 1) || wifi_bits(dbi, 0x710, 0x3f0000, 0x10000) ||
        wifi_bits(dbi, 0x80c, 0x1f00, 0x100) ||
        wifi_bits(dbi, 0x7c, 0x383ff, 0x38012) || wifi_bits(dbi, 0xb40, UINT32_MAX, 26) ||
        wifi_control16(dbi, 0xa0, 15, 1) || wifi_control16(dbi, 0x80, 3, 0) ||
        wifi_restore_bits(dbi, 0x8bc, 1, ro_before)) goto out;
    ro_changed = 0;
    uint32_t width = wifi_read(dbi, 0x80c), control = wifi_read(dbi, 0x80);
    if (width == UINT32_MAX || control == UINT32_MAX) goto out;
    wifi_write(dbi, 0x80c, width | (1u << 17));
    wifi_write(dbi, 0x80, (control & 0xffffu) | 0x20u);
    if (wifi_bits(elbi, 0x0c, UINT32_MAX, 0) || wifi_bits(elbi, 0x10, UINT32_MAX, 0) ||
        wifi_bits(elbi, 0x14, UINT32_MAX, 0) || wifi_bits(pcs, 0xec, 8, 0) ||
        wifi_bits(elbi, 0x2c, 1, 1)) goto out;
    stage = "link-training";
    uint64_t deadline;
    clock_interval_to_deadline(500, NSEC_PER_MSEC, &deadline);
    for (unsigned tick = 0; tick < 500 && mach_absolute_time() < deadline; tick++) {
        link = wifi_read(elbi, 0x74);
        polls++;
        if (link == UINT32_MAX) break;
        unsigned state = link & 31u;
        if (state >= 0x0d && state <= 0x14) {
            /* Like the vendor DBI accessor, avoid RX-idle clock gating while
             * sampling config, including a link that drops during the read. */
            if (wifi_bits(pcs, 0xec, 8, 8)) goto out;
            status = wifi_read(dbi, 0x80);
            if (wifi_bits(pcs, 0xec, 8, 0) || status == UINT32_MAX) goto out;
            unsigned speed = (status >> 16) & 15u, lanes = (status >> 20) & 63u;
            if (speed == 1 && lanes == 1) { trained = 1; break; }
            if (speed > 1 || lanes > 1) break;
        }
        delay_for_interval(1, NSEC_PER_MSEC);
    }
    wlog("Gen1 link %s: ELBI=%#x speed=%u lanes=%u; endpoint/DMA/firmware untouched\n",
        trained ? "up" : "not established", link, (status >> 16) & 15u, (status >> 20) & 63u);
    if (trained && mode >= 5) {
        if (wifi_bits(pcs, 0xec, 8, 8)) {
            wlog("endpoint probe skipped: DBI access prerequisite failed\n");
            goto out;
        }
        cleanup_failed |= wifi_endpoint_identity(regions, mode);
    }
out:
    if (!trained) wlog("Gen1 probe stopped: stage=%s polls=%u last_ELBI=%#x\n", stage, polls, link);
    /* Assert endpoint reset, stop training and force the vendor PHY power-down
     * state before the caller re-isolates and removes WLAN power. Internal
     * PHY/DBI programming is retained, not claimed to match S-Boot bytewise. */
    cleanup_failed |= wifi_restore_bits(gpio, 0x24, 4, 0);
    cleanup_failed |= wifi_restore_bits(elbi, 0x2c, 1, 0);
    cleanup_failed |= wifi_restore_bits(elbi, 0x0c, UINT32_MAX, 0);
    cleanup_failed |= wifi_restore_bits(elbi, 0x10, UINT32_MAX, 0);
    cleanup_failed |= wifi_restore_bits(elbi, 0x14, UINT32_MAX, 0);
    if (dbi_ready) {
        if (wifi_restore_bits(pcs, 0xec, 8, 8)) cleanup_failed = -1;
        else {
            int master_failed = -1;
            for (unsigned attempt = 0; attempt < 3; attempt++) {
                if (!wifi_control16(dbi, 0x04, 0x147, 2)) { master_failed = 0; break; }
                delay_for_interval(1, NSEC_PER_MSEC);
            }
            cleanup_failed |= master_failed;
            if (ro_changed) cleanup_failed |= wifi_restore_bits(dbi, 0x8bc, 1, ro_before);
        }
    }
    cleanup_failed |= wifi_restore_bits(phy, 0x15c, 0xff, 0xfe);
    cleanup_failed |= wifi_restore_bits(phy, 0x80, 0xff, 0xc1);
    cleanup_failed |= wifi_restore_bits(pcs, 0x100, 0x40, 0x40);
    cleanup_failed |= wifi_restore_bits(pcs, 0x104, 0x80, 0x80);
    cleanup_failed |= wifi_restore_bits(pcs, 0xec, 8, idle);
    cleanup_failed |= wifi_restore_bits(sysreg, 0x1044, 2, hs);
    cleanup_failed |= wifi_restore_bits(sysreg, 0x1050, 0x10fe, lane);
    cleanup_failed |= wifi_restore_bits(gpio, 0x20, 15, clock_mux);
    cleanup_failed |= wifi_restore_bits(gpio, 0x28, 15, clock_pull);
    for (unsigned i = 0; i < sizeof(saved) / sizeof(saved[0]); i++)
        cleanup_failed |= wifi_restore_bits(elbi, saved[i].off, saved[i].mask, saved[i].value);
    wlog("Gen1 quiesce %s; PHY power-down requested, PCIe IRQs stay masked\n",
        cleanup_failed ? "FAILED" : "verified");
}

static int
wifi_controller_snapshot(const struct wifi_region *elbi)
{
    static const unsigned offsets[] = { 0x02c, 0x074, 0x1d0, 0x288, 0x28c, 0x290 };
    wlog("ELBI snapshot begin: PERST held low, PHY bypass verified; read only\n");
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        uint32_t value = wifi_read(elbi, offsets[i]);
        wlog("ELBI +%#x raw=%#x\n", offsets[i], value);
        if (value == UINT32_MAX) {
            wlog("ELBI snapshot failed: all-ones register; stopping controller reads\n");
            return -1;
        }
    }
    wlog("ELBI snapshot complete; no controller writes, link training or endpoint access\n");
    return 0;
}

static void
wifi_power_probe(struct wifi_region *regions, uint32_t mode)
{
    const uint32_t wlan_function = 15u << 20, wlan_level = 1u << 5;
    const uint32_t reset_function = 15u << 8, reset_level = 1u << 2;
    uint32_t phy = wifi_read(&regions[0], 0x71c);
    uint32_t wc = wifi_read(&regions[1], 0x80), wd = wifi_read(&regions[1], 0x84);
    uint32_t rc = wifi_read(&regions[2], 0x20), rd = wifi_read(&regions[2], 0x24);
    /* This first active trial accepts only the idle state measured in epoch 48.
     * Do not interrupt an already-owned pin, powered PHY or active endpoint. */
    if (phy == UINT32_MAX || wc == UINT32_MAX || wd == UINT32_MAX ||
        rc == UINT32_MAX || rd == UINT32_MAX || (phy & 1u) ||
        (wc & wlan_function) || (wd & wlan_level) ||
        (rc & reset_function) || (rd & reset_level)) {
        wlog("power probe skipped: shared state differs from verified idle baseline\n");
        return;
    }
    /* Exact observed clock words; this probe changes no clock setting. These
     * checks do not authorize accessing ELBI/DBI or training the link. */
    for (unsigned off = 0x2030; off <= 0x2044; off += 4) {
        if (wifi_read(&regions[3], off) != 0x200000) {
            wlog("power probe skipped: gate +%#x differs from baseline\n", off);
            return;
        }
    }
    for (unsigned off = 0x3034; off <= 0x3044; off += 4) {
        if (wifi_read(&regions[3], off) != 0x3f0002) {
            wlog("power probe skipped: QCH +%#x differs from baseline\n", off);
            return;
        }
    }
    wlog("power probe begin: hold PERST low; temporary WLAN power and PHY bypass\n");
    /* Program low latches before selecting output. Modes 2/3 hold reset; mode
     * 4..6 temporarily release/reassert it inside the separate link probe. */
    int failed = wifi_bits(&regions[2], 0x24, reset_level, 0) ||
        wifi_bits(&regions[2], 0x20, reset_function, 1u << 8) ||
        wifi_bits(&regions[1], 0x84, wlan_level, 0) ||
        wifi_bits(&regions[1], 0x80, wlan_function, 1u << 20) ||
        wifi_bits(&regions[1], 0x84, wlan_level, wlan_level);
    if (!failed) {
        delay_for_interval(200, NSEC_PER_MSEC); /* Samsung WIFI_TURNON_DELAY */
        failed = wifi_bits(&regions[0], 0x71c, 1u, 1u);
        if (!failed) {
            delay_for_interval(1, NSEC_PER_MSEC);
            failed = (wifi_read(&regions[2], 0x24) & reset_level) != 0 ||
                (wifi_read(&regions[1], 0x84) & wlan_level) == 0;
        }
    }
    wlog("power probe readback %s\n", failed ? "failed" : "passed");
    if (!failed && mode >= 3 && !wifi_controller_snapshot(&regions[4]) && mode >= 4)
        wifi_gen1_probe(regions, mode);
    /* Re-isolate before powering down. Restore data while pads are still
     * outputs, then restore mux fields. Attempt every restoration on failure. */
    int restore_failed = 0;
    restore_failed |= wifi_restore_bits(&regions[0], 0x71c, 1u, phy);
    restore_failed |= wifi_restore_bits(&regions[1], 0x84, wlan_level, wd);
    restore_failed |= wifi_restore_bits(&regions[2], 0x24, reset_level, rd);
    restore_failed |= wifi_restore_bits(&regions[1], 0x80, wlan_function, wc);
    restore_failed |= wifi_restore_bits(&regions[2], 0x20, reset_function, rc);
    wlog("power probe restore %s; no firmware or networking\n", restore_failed ? "FAILED" : "verified");
}

void
b2l_wifi_diag_start(void)
{
    uint32_t mode = 0;
    struct wifi_region regions[] = {
        { 0x15860000, 0, 0x4000 }, /* PMU: PCIe0 PHY isolation */
        { 0x10430000, 0, 0x4000 }, /* PERIC0 GPIO: GPG0-5 WLAN_REG_ON */
        { 0x13c40000, 0, 0x4000 }, /* FSYS1 GPIO: GPF2-0 CLKREQ, GPF2-2 PERST */
        { 0x13c00000, 0, 0x4000 }, /* CMU_FSYS1, shared with booted UFS */
        { 0x13ed0000, 0, 0x4000 }, /* PCIe0 ELBI, modes 3/4/5 */
        { 0x13ef0000, 0, 0x4000 }, /* PCIe0 PHY, modes 4/5 */
        { 0x13ee0000, 0, 0x4000 }, /* PCIe0 PCS */
        { 0x13c10000, 0, 0x4000 }, /* SYSREG_FSYS1, PCIe0 fields only */
        { 0x13f00000, 0, 0x4000 }, /* PCIe0 root DBI */
        { 0x14ffc000, 0, 0x4000 }, /* Modes 5/6: only CFG0 +0x2000 */
        { 0x14400000, 0, 0x4000 }, /* Mode 6: BAR0 first-page chipcommon reads */
    };
    static const unsigned gates[] = { 0x2030, 0x2034, 0x2038, 0x203c, 0x2040, 0x2044 };
    static const unsigned qch[] = { 0x3034, 0x3038, 0x303c, 0x3040, 0x3044 };
    unsigned count = 4;

    if (!PE_parse_boot_argn("b2l_wifi_diag", &mode, sizeof(mode)) || mode < 1 || mode > 6) {
        wlog("diagnostic disabled; no MMIO access\n");
        return;
    }
    if (mode == 3) count = 5;
    if (mode == 4) count = 9;
    if (mode == 5) count = 10;
    if (mode == 6) count = sizeof(regions) / sizeof(regions[0]);
    /* Map every shared block before reading any of them. Release all mappings
     * even when an allocation fails. Mode 3 also maps ELBI, but cannot read it
     * until the verified power/reset/isolation sequence has completed. */
    for (unsigned i = 0; i < count; i++) {
        regions[i].mapped = ml_io_map_unmappable(regions[i].physical,
            regions[i].size, VM_WIMG_IO);
        if (!regions[i].mapped) {
            wlog("shared-block map failed at %#lx; no registers sampled\n",
                (unsigned long)regions[i].physical);
            goto out;
        }
    }
    wlog("shared-block snapshot begin; no PCIe controller access\n");
    uint32_t phy = wifi_read(&regions[0], 0x71c);
    uint32_t wlan_con = wifi_read(&regions[1], 0x80);
    uint32_t wlan_dat = wifi_read(&regions[1], 0x84);
    uint32_t pcie_con = wifi_read(&regions[2], 0x20);
    uint32_t pcie_dat = wifi_read(&regions[2], 0x24);
    wlog("PMU PHY_CONTROL=%#x; GPG0 CON=%#x DAT=%#x; GPF2 CON=%#x DAT=%#x\n",
        phy, wlan_con, wlan_dat, pcie_con, pcie_dat);
    if (phy == UINT32_MAX || wlan_con == UINT32_MAX || wlan_dat == UINT32_MAX ||
        pcie_con == UINT32_MAX || pcie_dat == UINT32_MAX) {
        wlog("invalid all-ones shared register; pin state undecoded\n");
        goto out;
    }
    wlog("PHY isolation_bypass=%u; WLAN_REG_ON function=%u level=%u; "
        "PERST function=%u level=%u; CLKREQ function=%u level=%u\n",
        phy & 1u, (wlan_con >> 20) & 15u, (wlan_dat >> 5) & 1u,
        (pcie_con >> 8) & 15u, (pcie_dat >> 2) & 1u,
        pcie_con & 15u, pcie_dat & 1u);
    for (unsigned i = 0; i < sizeof(gates) / sizeof(gates[0]); i++) {
        uint32_t value = wifi_read(&regions[3], gates[i]);
        wlog("CMU gate +%#x raw=%#x\n", gates[i], value);
    }
    for (unsigned i = 0; i < sizeof(qch) / sizeof(qch[0]); i++) {
        uint32_t value = wifi_read(&regions[3], qch[i]);
        wlog("CMU QCH +%#x raw=%#x\n", qch[i], value);
    }
    wlog("snapshot complete; PCI identity, firmware and Wi-Fi remain unprobed\n");
    if (mode >= 2) wifi_power_probe(regions, mode);
out:
    for (unsigned i = count; i > 0; i--) {
        if (regions[i - 1].mapped)
            ml_io_unmap(regions[i - 1].mapped, regions[i - 1].size);
    }
}
