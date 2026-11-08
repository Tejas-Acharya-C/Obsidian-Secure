import json

with open('screenshots/manifest.json', 'r') as f:
    data = json.load(f)

print(f"Total entries: {len(data)}")
viewports = sorted(list(set(d['width'] for d in data)))
pages = sorted(list(set(d['page'] for d in data)))
print(f"Viewports tested ({len(viewports)}): {viewports}")
print(f"Pages tested ({len(pages)}): {pages}")

overflow_entries = [d for d in data if d.get('has_horizontal_overflow') or d.get('overflow_px', 0) > 0]
print(f"\nOverflow entries detected: {len(overflow_entries)}")
for ov in overflow_entries:
    print(f"  [OVERFLOW] Page: {ov['page']} at {ov['width']}px (scrollWidth={ov['scroll_width']}, clientWidth={ov['client_width']}, ov={ov['overflow_px']}px)")

print("\nViewport Breakdown:")
for vp in viewports:
    vp_entries = [d for d in data if d['width'] == vp]
    success_count = sum(1 for d in vp_entries if d['success'])
    max_ov = max(d['overflow_px'] for d in vp_entries)
    cw = vp_entries[0]['client_width']
    sw = vp_entries[0]['scroll_width']
    print(f"  {vp:4d}px : {success_count}/{len(vp_entries)} captured | clientWidth={cw}px, scrollWidth={sw}px | max_overflow={max_ov}px")
