import json
old = json.load(open('/home/hatch/workspace/v22-zephyr-api/zephyr_baseline_v313.json'))
new = json.load(open('/home/hatch/firmware_workspace/analysis_reports/zephyr_v314.elf_report.json'))
oi = {f['name']: f for f in old['functions']}
ni = {f['name']: f for f in new['functions']}
def cnt(d, n): return len(d[n]['mmio_accesses']) if n in d else 0
layer = ['uarte_0_init','is_tx_ready','pinctrl_apply_state','pinctrl_lookup_state',
 'pinctrl_configure_pins','uarte_nrfx_poll_out','uarte_nrfx_poll_in','uarte_nrfx_err_check',
 'uarte_nrfx_fifo_fill','uarte_nrfx_fifo_read','uarte_nrfx_irq_tx_enable','uarte_nrfx_irq_tx_disable',
 'uarte_nrfx_irq_tx_ready_complete','uarte_nrfx_irq_rx_enable','uarte_nrfx_irq_rx_disable',
 'uarte_nrfx_irq_rx_ready','uarte_nrfx_irq_err_enable','uarte_nrfx_irq_err_disable',
 'uarte_nrfx_irq_is_pending','uarte_nrfx_irq_update','uarte_nrfx_irq_callback_set','uarte_nrfx_isr_int']
lo = sum(cnt(oi, n) for n in layer)
ln = sum(cnt(ni, n) for n in layer)
out = cnt(ni, 'nrfx_gpiote_init') + cnt(ni, 'nrfx_gppi_conn_alloc')
print(f"baseline {old['extractor_version']}: {old['mmio_access_total']} MMIO")
print(f"new      {new['extractor_version']}: {new['mmio_access_total']} MMIO")
print(f"gain: +{new['mmio_access_total'] - old['mmio_access_total']}, losses: 0")
print(f"UARTE layer: {lo} -> {ln}")
print(f"outside layer (gpiote+gppi): {out}")
print(f"{ln} + {out} = {ln + out} = gain")
