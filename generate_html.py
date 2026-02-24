#!/usr/bin/env python3
"""Generate comprehensive HTML from all markdown files."""

import os
import re
from pathlib import Path

def escape_html(text):
    """Escape HTML special characters."""
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def markdown_to_html(md_content, section_id):
    """Convert markdown to HTML with proper formatting."""
    lines = md_content.split('\n')
    html_lines = []
    in_code_block = False
    code_lang = ''
    code_content = []
    in_table = False
    table_content = []

    for line in lines:
        # Code blocks
        if line.startswith('```'):
            if in_code_block:
                # End code block
                code_html = escape_html('\n'.join(code_content))
                html_lines.append(f'<pre><code class="language-{code_lang}">{code_html}</code></pre>')
                in_code_block = False
                code_content = []
                code_lang = ''
            else:
                # Start code block
                in_code_block = True
                code_lang = line[3:].strip() or 'text'
            continue

        if in_code_block:
            code_content.append(line)
            continue

        # Tables
        if '|' in line and line.strip().startswith('|'):
            if not in_table:
                in_table = True
                table_content = []
            table_content.append(line)
            continue
        elif in_table:
            # End table
            html_lines.append(convert_table(table_content))
            in_table = False
            table_content = []

        # Headers
        if line.startswith('# '):
            text = line[2:]
            html_lines.append(f'<h1>{escape_html(text)}</h1>')
        elif line.startswith('## '):
            text = line[3:]
            anchor = re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')
            html_lines.append(f'<h2 id="{section_id}-{anchor}">{escape_html(text)}</h2>')
        elif line.startswith('### '):
            text = line[4:]
            html_lines.append(f'<h3>{escape_html(text)}</h3>')
        elif line.startswith('#### '):
            text = line[5:]
            html_lines.append(f'<h4>{escape_html(text)}</h4>')
        elif line.startswith('---'):
            html_lines.append('<hr>')
        elif line.startswith('- '):
            html_lines.append(f'<li>{escape_html(line[2:])}</li>')
        elif line.startswith('* '):
            html_lines.append(f'<li>{escape_html(line[2:])}</li>')
        elif re.match(r'^\d+\. ', line):
            text = re.sub(r'^\d+\. ', '', line)
            html_lines.append(f'<li>{escape_html(text)}</li>')
        elif line.strip():
            # Regular paragraph - handle inline formatting
            text = escape_html(line)
            # Bold
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            # Italic
            text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
            # Inline code
            text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
            # Links
            text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', text)
            html_lines.append(f'<p>{text}</p>')
        else:
            html_lines.append('')

    # Handle any remaining table
    if in_table:
        html_lines.append(convert_table(table_content))

    return '\n'.join(html_lines)

def convert_table(table_lines):
    """Convert markdown table to HTML."""
    if len(table_lines) < 2:
        return '<pre>' + escape_html('\n'.join(table_lines)) + '</pre>'

    html = ['<table>']
    for i, line in enumerate(table_lines):
        if '---' in line and i == 1:
            continue  # Skip separator line
        cells = [c.strip() for c in line.split('|')[1:-1]]
        if i == 0:
            html.append('<thead><tr>')
            for cell in cells:
                html.append(f'<th>{escape_html(cell)}</th>')
            html.append('</tr></thead><tbody>')
        else:
            html.append('<tr>')
            for cell in cells:
                html.append(f'<td>{escape_html(cell)}</td>')
            html.append('</tr>')
    html.append('</tbody></table>')
    return '\n'.join(html)

def generate_html():
    """Generate the complete HTML file."""
    base_dir = Path('/Users/m.s.deepak/Documents/Security-Ref-Guide')

    # File order and metadata
    files = [
        ('00_INDEX.md', 'index', 'Index', '#00d4ff'),
        ('01_FUNDAMENTALS.md', 'fundamentals', 'Network Fundamentals', '#00d4ff'),
        ('02_CRYPTOGRAPHY.md', 'cryptography', 'Cryptography', '#00d4ff'),
        ('03_AUTH_IDENTITY.md', 'auth', 'Authentication & Identity', '#00d4ff'),
        ('04_MITRE_ATTACK.md', 'mitre', 'MITRE ATT&CK', '#ff6b6b'),
        ('05_DETECTION_ENGINEERING.md', 'detection', 'Detection Engineering', '#51cf66'),
        ('06_INCIDENT_RESPONSE.md', 'ir', 'Incident Response', '#51cf66'),
        ('07_THREAT_HUNTING.md', 'hunting', 'Threat Hunting', '#51cf66'),
        ('08_MALWARE_RANSOMWARE.md', 'malware', 'Malware & Ransomware', '#ff6b6b'),
        ('09_WINDOWS_SECURITY.md', 'windows', 'Windows Security', '#be63f9'),
        ('10_LINUX_SECURITY.md', 'linux', 'Linux Security', '#be63f9'),
        ('11_CLOUD_SECURITY.md', 'cloud', 'Cloud Security', '#be63f9'),
        ('12_WEB_API_SECURITY.md', 'web', 'Web & API Security', '#ffa94d'),
        ('13_AI_ML_SECURITY.md', 'aiml', 'AI/ML Security', '#ffa94d'),
        ('14_TOOLS_REFERENCE.md', 'tools', 'Tools Reference', '#ffd43b'),
        ('15_INTERVIEW_QUESTIONS.md', 'interview', 'Interview Questions', '#ffd43b'),
        ('16_PYTHON_AUTOMATION.md', 'python', 'Python Automation', '#51cf66'),
    ]

    # Read all files
    sections = []
    nav_items = []
    total_lines = 0

    for filename, section_id, title, color in files:
        filepath = base_dir / filename
        if filepath.exists():
            content = filepath.read_text()
            line_count = len(content.split('\n'))
            total_lines += line_count
            html_content = markdown_to_html(content, section_id)
            sections.append((section_id, title, html_content, color))
            nav_items.append((section_id, title, color, line_count))

    # Generate HTML
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Reference Guide - Interview Prep</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --accent-cyan: #00d4ff;
            --accent-red: #ff6b6b;
            --accent-green: #51cf66;
            --accent-purple: #be63f9;
            --accent-orange: #ffa94d;
            --accent-yellow: #ffd43b;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        /* Sidebar */
        .sidebar {{
            position: fixed;
            top: 0;
            left: 0;
            width: 280px;
            height: 100vh;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            overflow-y: auto;
            z-index: 1000;
        }}

        .sidebar-header {{
            padding: 20px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
            position: sticky;
            top: 0;
        }}

        .sidebar-header h1 {{
            font-size: 1.1rem;
            color: var(--accent-cyan);
            margin-bottom: 10px;
        }}

        .sidebar-header .stats {{
            font-size: 0.75rem;
            color: var(--text-secondary);
        }}

        #search {{
            width: 100%;
            padding: 8px 12px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            margin-top: 10px;
        }}

        #search:focus {{
            outline: none;
            border-color: var(--accent-cyan);
        }}

        .nav-list {{
            list-style: none;
            padding: 10px 0;
        }}

        .nav-item {{
            display: block;
            padding: 10px 20px;
            color: var(--text-primary);
            text-decoration: none;
            border-left: 3px solid transparent;
            transition: all 0.2s;
            font-size: 0.9rem;
        }}

        .nav-item:hover {{
            background: var(--bg-tertiary);
        }}

        .nav-item.active {{
            background: var(--bg-tertiary);
        }}

        .nav-item .lines {{
            float: right;
            font-size: 0.75rem;
            color: var(--text-secondary);
        }}

        /* Main content */
        .main {{
            margin-left: 280px;
            padding: 40px 60px;
            max-width: 1200px;
        }}

        .section {{
            margin-bottom: 60px;
            padding: 30px;
            background: var(--bg-secondary);
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}

        h1 {{ font-size: 2rem; margin-bottom: 20px; }}
        h2 {{ font-size: 1.5rem; margin: 30px 0 15px; padding-top: 20px; border-top: 1px solid var(--border-color); }}
        h3 {{ font-size: 1.2rem; margin: 20px 0 10px; color: var(--text-secondary); }}
        h4 {{ font-size: 1rem; margin: 15px 0 8px; }}

        p {{ margin: 10px 0; }}

        pre {{
            background: var(--bg-primary);
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
            margin: 15px 0;
            border: 1px solid var(--border-color);
        }}

        code {{
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
            font-size: 0.85rem;
        }}

        p code {{
            background: var(--bg-tertiary);
            padding: 2px 6px;
            border-radius: 4px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}

        th, td {{
            padding: 10px 12px;
            border: 1px solid var(--border-color);
            text-align: left;
        }}

        th {{
            background: var(--bg-tertiary);
        }}

        tr:nth-child(even) {{
            background: var(--bg-primary);
        }}

        li {{
            margin: 5px 0 5px 20px;
        }}

        a {{
            color: var(--accent-cyan);
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        hr {{
            border: none;
            border-top: 1px solid var(--border-color);
            margin: 30px 0;
        }}

        /* Back to top */
        #back-to-top {{
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 50px;
            height: 50px;
            background: var(--accent-cyan);
            color: var(--bg-primary);
            border: none;
            border-radius: 50%;
            cursor: pointer;
            font-size: 1.5rem;
            display: none;
            z-index: 1000;
        }}

        #back-to-top:hover {{
            background: var(--accent-green);
        }}

        /* Mobile */
        @media (max-width: 768px) {{
            .sidebar {{
                transform: translateX(-100%);
                transition: transform 0.3s;
            }}
            .sidebar.open {{
                transform: translateX(0);
            }}
            .main {{
                margin-left: 0;
                padding: 20px;
            }}
            .mobile-toggle {{
                display: block;
                position: fixed;
                top: 10px;
                left: 10px;
                z-index: 1001;
                background: var(--bg-tertiary);
                border: 1px solid var(--border-color);
                color: var(--text-primary);
                padding: 10px 15px;
                border-radius: 6px;
                cursor: pointer;
            }}
        }}

        @media (min-width: 769px) {{
            .mobile-toggle {{ display: none; }}
        }}

        /* Print */
        @media print {{
            .sidebar, #back-to-top, .mobile-toggle {{ display: none !important; }}
            .main {{ margin-left: 0; padding: 20px; }}
            body {{ background: white; color: black; }}
            .section {{ border: 1px solid #ccc; }}
            pre {{ background: #f5f5f5; }}
        }}
    </style>
</head>
<body>
    <button class="mobile-toggle" onclick="document.querySelector('.sidebar').classList.toggle('open')">Menu</button>

    <nav class="sidebar">
        <div class="sidebar-header">
            <h1>Security Reference Guide</h1>
            <div class="stats">{len(sections)} sections | {total_lines:,} lines</div>
            <input type="text" id="search" placeholder="Search..." onkeyup="filterNav()">
        </div>
        <ul class="nav-list">
'''

    # Add nav items
    for section_id, title, color, line_count in nav_items:
        html += f'''            <li><a href="#{section_id}" class="nav-item" style="border-left-color: {color}">{title}<span class="lines">{line_count}</span></a></li>\n'''

    html += '''        </ul>
    </nav>

    <main class="main">
'''

    # Add sections
    for section_id, title, content, color in sections:
        html += f'''        <section id="{section_id}" class="section" style="border-top: 3px solid {color}">
{content}
        </section>
'''

    html += '''    </main>

    <button id="back-to-top" onclick="window.scrollTo({top:0,behavior:'smooth'})">↑</button>

    <script>
        // Back to top button
        window.onscroll = function() {
            const btn = document.getElementById('back-to-top');
            if (document.documentElement.scrollTop > 300) {
                btn.style.display = 'block';
            } else {
                btn.style.display = 'none';
            }

            // Update active nav
            const sections = document.querySelectorAll('.section');
            const navItems = document.querySelectorAll('.nav-item');
            let current = '';

            sections.forEach(section => {
                const sectionTop = section.offsetTop;
                if (scrollY >= sectionTop - 100) {
                    current = section.getAttribute('id');
                }
            });

            navItems.forEach(item => {
                item.classList.remove('active');
                if (item.getAttribute('href') === '#' + current) {
                    item.classList.add('active');
                }
            });
        };

        // Search filter
        function filterNav() {
            const query = document.getElementById('search').value.toLowerCase();
            const items = document.querySelectorAll('.nav-item');
            items.forEach(item => {
                const text = item.textContent.toLowerCase();
                item.parentElement.style.display = text.includes(query) ? '' : 'none';
            });
        }

        // Smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            });
        });
    </script>
</body>
</html>'''

    # Write file
    output_path = base_dir / 'Security-Reference-Guide.html'
    output_path.write_text(html)
    print(f"Generated: {output_path}")
    print(f"Total sections: {len(sections)}")
    print(f"Total lines: {total_lines:,}")

    # Get file size
    size = output_path.stat().st_size
    print(f"File size: {size:,} bytes ({size/1024/1024:.1f} MB)")

if __name__ == '__main__':
    generate_html()
