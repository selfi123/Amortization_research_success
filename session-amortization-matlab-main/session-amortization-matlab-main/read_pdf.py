import pdfplumber
import sys

# Force UTF-8 output
sys.stdout.reconfigure(encoding='utf-8')

pdf_path = r'C:\Users\aloob\Downloads\Research Backup\A post-quantum lattice based lightweight authentication and code-based.pdf'

with pdfplumber.open(pdf_path) as pdf:
    print(f'TOTAL PAGES: {len(pdf.pages)}')
    for i, page in enumerate(pdf.pages):
        print(f'\n========== PAGE {i+1} ==========')
        text = page.extract_text()
        if text:
            print('[TEXT CONTENT]')
            print(text)
        else:
            print('[NO TEXT EXTRACTED ON THIS PAGE]')
        tables = page.extract_tables()
        if tables:
            print(f'\n[TABLES FOUND: {len(tables)}]')
            for ti, tbl in enumerate(tables):
                print(f'  Table {ti+1}: {tbl}')
        images = page.images
        if images:
            print(f'\n[EMBEDDED IMAGE OBJECTS: {len(images)}]')
            for img in images:
                x0 = img.get('x0', 0)
                y0 = img.get('y0', 0)
                x1 = img.get('x1', 0)
                y1 = img.get('y1', 0)
                w = img.get('width', '?')
                h = img.get('height', '?')
                print(f'  Image bbox: x0={x0:.1f}, y0={y0:.1f}, x1={x1:.1f}, y1={y1:.1f}, width={w}, height={h}')
        rects = page.rects
        if rects:
            print(f'[RECT OBJECTS (possible figure borders): {len(rects)}]')
