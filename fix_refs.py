import re

with open('paper/main.tex', 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if '\\doi{' in line:
        # replace \doi{...} with Available: \url{https://doi.org/...}
        lines[i] = re.sub(r'\\doi{([^}]+)}', r'Available: \\url{https://doi.org/\1}', line)
        
        # small fix for line 1134
        if 'at Available:' in lines[i]:
             lines[i] = lines[i].replace('at Available:', 'Available at:')

with open('paper/main.tex', 'w') as f:
    f.writelines(lines)
