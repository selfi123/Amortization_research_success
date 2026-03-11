import sys

with open('paper/main.tex', 'r') as f:
    lines = f.readlines()

homoglyphs = {
    # Cyrillic
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X',
    # Greek
    'ο': 'o', 'ν': 'v',
}

found = 0
for i, line in enumerate(lines):
    for j, char in enumerate(line):
        if char in homoglyphs:
            print(f"Line {i+1}, Col {j+1}: '{char}' (U+{ord(char):04X}) replacing '{homoglyphs[char]}'")
            found += 1
            
print(f"Total found: {found}")
