import re
import os

# Resolve the .tex path relative to this script (works from any cwd).
HERE = os.path.dirname(os.path.abspath(__file__))
TEX = os.path.join(HERE, "agent_cryptid.tex")

with open(TEX, 'r', encoding='utf-8') as f:
    content = f.read()

# Extract all \cite{...} keys (may be comma-separated lists)
cite_pattern = re.compile(r'\\cite\{([^}]+)\}')
cites = set()
for m in cite_pattern.finditer(content):
    for key in m.group(1).split(','):
        key = key.strip()
        if key:
            cites.add(key)

# Extract all \bibitem{...} keys
bib_pattern = re.compile(r'\\bibitem\{([^}]+)\}')
bibitems = set()
for m in bib_pattern.finditer(content):
    bibitems.add(m.group(1).strip())

print(f'Total unique citations: {len(cites)}')
print(f'Total bibitems: {len(bibitems)}')

# Find citations without bibitems
missing = cites - bibitems
if missing:
    print(f'\nMISSING BIBITEMS ({len(missing)}):')
    for m in sorted(missing):
        print(f'  {m}')
else:
    print('\nAll citations have matching bibitems. [0 missing]')

# Find bibitems without citations
unused = bibitems - cites
if unused:
    print(f'\nUNUSED BIBITEMS ({len(unused)}):')
    for u in sorted(unused):
        print(f'  {u}')
else:
    print('No unused bibitems. [0 unused]')

print(f'\nCitation density: {len(cites)} references cited in paper.')
if not missing and not unused:
    print('STATUS: CONSISTENT (citations == bibitems, no undefined, no dead refs).')
