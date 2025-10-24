#!/usr/bin/env python3
"""
Convert Markdown to PDF with proper styling for Chinese content
"""

import markdown
from weasyprint import HTML, CSS
from pathlib import Path

def convert_md_to_pdf(md_file, pdf_file):
    """Convert markdown file to PDF with styling"""

    # Read markdown content
    with open(md_file, 'r', encoding='utf-8') as f:
        md_content = f.read()

    # Convert markdown to HTML
    md = markdown.Markdown(extensions=[
        'extra',           # Tables, fenced code blocks, etc.
        'codehilite',      # Code syntax highlighting
        'toc',             # Table of contents
        'nl2br',           # Newline to <br>
    ])
    html_body = md.convert(md_content)

    # Create styled HTML document
    html_template = f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>eBPF 网络故障排查工具集介绍</title>
        <style>
            @page {{
                size: A4;
                margin: 2cm;
                @bottom-right {{
                    content: counter(page) " / " counter(pages);
                    font-size: 9pt;
                    color: #666;
                }}
            }}

            body {{
                font-family: "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei",
                             "WenQuanYi Micro Hei", Arial, sans-serif;
                font-size: 11pt;
                line-height: 1.6;
                color: #333;
                max-width: 100%;
            }}

            h1 {{
                color: #277884;
                font-size: 24pt;
                font-weight: bold;
                margin-top: 20pt;
                margin-bottom: 12pt;
                page-break-after: avoid;
                border-bottom: 3pt solid #277884;
                padding-bottom: 8pt;
            }}

            h2 {{
                color: #277884;
                font-size: 18pt;
                font-weight: bold;
                margin-top: 16pt;
                margin-bottom: 10pt;
                page-break-after: avoid;
                border-left: 4pt solid #5EA8A7;
                padding-left: 10pt;
            }}

            h3 {{
                color: #2C2C2C;
                font-size: 14pt;
                font-weight: bold;
                margin-top: 12pt;
                margin-bottom: 8pt;
                page-break-after: avoid;
            }}

            h4 {{
                color: #2C2C2C;
                font-size: 12pt;
                font-weight: bold;
                margin-top: 10pt;
                margin-bottom: 6pt;
            }}

            p {{
                margin: 6pt 0;
                text-align: justify;
            }}

            ul, ol {{
                margin: 8pt 0;
                padding-left: 30pt;
            }}

            li {{
                margin: 4pt 0;
            }}

            code {{
                background-color: #F5F5F5;
                padding: 2pt 4pt;
                border-radius: 3pt;
                font-family: "Consolas", "Monaco", "Courier New", monospace;
                font-size: 10pt;
                color: #E74C3C;
            }}

            pre {{
                background-color: #F5F5F5;
                border-left: 4pt solid #5EA8A7;
                padding: 12pt;
                margin: 10pt 0;
                overflow-x: auto;
                page-break-inside: avoid;
            }}

            pre code {{
                background-color: transparent;
                padding: 0;
                color: #2C2C2C;
                font-size: 9pt;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 12pt 0;
                font-size: 10pt;
                page-break-inside: avoid;
            }}

            th {{
                background-color: #277884;
                color: white;
                padding: 8pt;
                text-align: left;
                font-weight: bold;
                border: 1pt solid #CCCCCC;
            }}

            td {{
                padding: 8pt;
                border: 1pt solid #CCCCCC;
            }}

            tr:nth-child(even) {{
                background-color: #F9F9F9;
            }}

            blockquote {{
                border-left: 4pt solid #FE4447;
                margin: 10pt 0;
                padding: 8pt 12pt;
                background-color: #FFF3F3;
                font-style: italic;
            }}

            hr {{
                border: none;
                border-top: 2pt solid #E0E0E0;
                margin: 20pt 0;
            }}

            .highlight {{
                background-color: #FFF3CD;
                padding: 2pt 4pt;
                border-radius: 3pt;
            }}

            strong {{
                color: #277884;
                font-weight: bold;
            }}

            em {{
                color: #FE4447;
                font-style: italic;
            }}

            a {{
                color: #5EA8A7;
                text-decoration: none;
            }}

            a:hover {{
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        {html_body}
    </body>
    </html>
    """

    # Convert HTML to PDF
    HTML(string=html_template).write_pdf(pdf_file)
    print(f"PDF generated successfully: {pdf_file}")

if __name__ == "__main__":
    md_file = "/Users/admin/workspace/troubleshooting-tools/docs/publish/network-troubleshooting-tools-demo-report-streamlined.md"
    pdf_file = "/Users/admin/workspace/troubleshooting-tools/docs/publish/network-troubleshooting-tools-demo-report.pdf"

    convert_md_to_pdf(md_file, pdf_file)
