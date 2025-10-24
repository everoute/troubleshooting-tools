#!/usr/bin/env python3
"""
Convert Markdown to styled HTML
"""

import markdown2
from pathlib import Path

def convert_md_to_html(md_file, html_file):
    """Convert markdown file to styled HTML"""

    # Read markdown content
    with open(md_file, 'r', encoding='utf-8') as f:
        md_content = f.read()

    # Convert markdown to HTML with extras
    html_body = markdown2.markdown(md_content, extras=[
        'fenced-code-blocks',
        'tables',
        'header-ids',
        'toc',
        'code-friendly',
        'break-on-newline',
    ])

    # Create styled HTML document
    html_template = f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>eBPF 网络故障排查工具集介绍</title>
        <style>
            @media print {{
                @page {{
                    size: A4;
                    margin: 2cm;
                }}

                body {{
                    font-size: 10pt;
                }}

                h1 {{
                    page-break-before: always;
                }}

                h1:first-of-type {{
                    page-break-before: avoid;
                }}

                h1, h2, h3, h4 {{
                    page-break-after: avoid;
                }}

                pre, table, blockquote {{
                    page-break-inside: avoid;
                }}
            }}

            body {{
                font-family: "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei",
                             "WenQuanYi Micro Hei", Arial, sans-serif;
                font-size: 14px;
                line-height: 1.8;
                color: #333;
                max-width: 900px;
                margin: 0 auto;
                padding: 40px 20px;
                background-color: #fff;
            }}

            h1 {{
                color: #277884;
                font-size: 32px;
                font-weight: bold;
                margin-top: 40px;
                margin-bottom: 20px;
                border-bottom: 4px solid #277884;
                padding-bottom: 10px;
            }}

            h1:first-of-type {{
                margin-top: 0;
                border-bottom: none;
                text-align: center;
                font-size: 36px;
                color: #277884;
            }}

            h2 {{
                color: #277884;
                font-size: 24px;
                font-weight: bold;
                margin-top: 30px;
                margin-bottom: 15px;
                border-left: 5px solid #5EA8A7;
                padding-left: 15px;
            }}

            h3 {{
                color: #2C2C2C;
                font-size: 20px;
                font-weight: bold;
                margin-top: 25px;
                margin-bottom: 12px;
            }}

            h4 {{
                color: #2C2C2C;
                font-size: 16px;
                font-weight: bold;
                margin-top: 20px;
                margin-bottom: 10px;
            }}

            p {{
                margin: 10px 0;
                text-align: justify;
            }}

            ul, ol {{
                margin: 15px 0;
                padding-left: 40px;
            }}

            li {{
                margin: 8px 0;
            }}

            code {{
                background-color: #F5F5F5;
                padding: 3px 6px;
                border-radius: 3px;
                font-family: "Consolas", "Monaco", "Courier New", monospace;
                font-size: 13px;
                color: #E74C3C;
            }}

            pre {{
                background-color: #F5F5F5;
                border-left: 5px solid #5EA8A7;
                padding: 15px;
                margin: 20px 0;
                overflow-x: auto;
                border-radius: 4px;
            }}

            pre code {{
                background-color: transparent;
                padding: 0;
                color: #2C2C2C;
                font-size: 13px;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                font-size: 13px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}

            th {{
                background-color: #277884;
                color: white;
                padding: 12px;
                text-align: left;
                font-weight: bold;
                border: 1px solid #CCCCCC;
            }}

            td {{
                padding: 10px 12px;
                border: 1px solid #CCCCCC;
            }}

            tr:nth-child(even) {{
                background-color: #F9F9F9;
            }}

            tr:hover {{
                background-color: #F0F0F0;
            }}

            blockquote {{
                border-left: 5px solid #FE4447;
                margin: 20px 0;
                padding: 10px 20px;
                background-color: #FFF3F3;
                font-style: italic;
            }}

            hr {{
                border: none;
                border-top: 2px solid #E0E0E0;
                margin: 30px 0;
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
                border-bottom: 1px dotted #5EA8A7;
            }}

            a:hover {{
                color: #277884;
                border-bottom: 1px solid #277884;
            }}

            /* Table of contents */
            #toc {{
                background-color: #F8F9FA;
                border: 2px solid #277884;
                border-radius: 5px;
                padding: 20px;
                margin: 30px 0;
            }}

            #toc ul {{
                list-style-type: none;
                padding-left: 20px;
            }}

            #toc li {{
                margin: 5px 0;
            }}

            #toc a {{
                color: #277884;
                border-bottom: none;
            }}

            /* Print-friendly */
            @media print {{
                body {{
                    max-width: 100%;
                    padding: 0;
                }}

                a {{
                    color: #277884;
                    text-decoration: none;
                    border-bottom: none;
                }}
            }}
        </style>
    </head>
    <body>
        {html_body}
    </body>
    </html>
    """

    # Write HTML file
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_template)

    print(f"HTML generated successfully: {html_file}")

if __name__ == "__main__":
    md_file = "/Users/admin/workspace/troubleshooting-tools/docs/publish/network-troubleshooting-tools-demo-report-streamlined.md"
    html_file = "/Users/admin/workspace/troubleshooting-tools/docs/publish/network-troubleshooting-tools-demo-report.html"

    convert_md_to_html(md_file, html_file)
