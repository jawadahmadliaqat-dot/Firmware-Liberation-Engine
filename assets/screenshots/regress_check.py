import re
lines = open('/home/hatch/workspace/v22-zephyr-api/regression_v314.txt').read().splitlines()
rows = [l for l in lines if '| got v3.14' in l]
bad = []
for l in rows:
    m = re.match(r'(.+?) \| exp_mmio=(\d+) exp_ports=(\d+) \| got v3.14 (\d+) (\d+)', l)
    if not m or int(m.group(2)) != int(m.group(4)) or int(m.group(3)) != int(m.group(5)):
        bad.append(l)
print(f"targets checked: {len(rows)}")
print(f"mismatches: {len(bad)}")
print("--- tail ---")
for l in lines[-4:]:
    print(l)
