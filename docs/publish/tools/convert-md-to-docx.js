const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
        HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
        VerticalAlign, LevelFormat, PageBreak } = require('docx');

// Read markdown file
const mdContent = fs.readFileSync('/Users/admin/workspace/troubleshooting-tools/docs/publish/network-troubleshooting-tools-demo-report-streamlined.md', 'utf-8');

// Simple markdown parser for this specific document
function parseMarkdown(md) {
    const lines = md.split('\n');
    const elements = [];
    let inCodeBlock = false;
    let codeBlockLines = [];
    let listItems = [];
    let inList = false;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Handle code blocks
        if (line.startsWith('```')) {
            if (inCodeBlock) {
                // End code block
                if (codeBlockLines.length > 0) {
                    elements.push({
                        type: 'code',
                        content: codeBlockLines.join('\n')
                    });
                }
                codeBlockLines = [];
                inCodeBlock = false;
            } else {
                inCodeBlock = true;
            }
            continue;
        }

        if (inCodeBlock) {
            codeBlockLines.push(line);
            continue;
        }

        // Handle headings
        if (line.startsWith('# ')) {
            if (inList) {
                elements.push({ type: 'list', items: listItems });
                listItems = [];
                inList = false;
            }
            elements.push({ type: 'h1', text: line.substring(2).trim() });
        } else if (line.startsWith('## ')) {
            if (inList) {
                elements.push({ type: 'list', items: listItems });
                listItems = [];
                inList = false;
            }
            elements.push({ type: 'h2', text: line.substring(3).trim() });
        } else if (line.startsWith('### ')) {
            if (inList) {
                elements.push({ type: 'list', items: listItems });
                listItems = [];
                inList = false;
            }
            elements.push({ type: 'h3', text: line.substring(4).trim() });
        } else if (line.startsWith('#### ')) {
            if (inList) {
                elements.push({ type: 'list', items: listItems });
                listItems = [];
                inList = false;
            }
            elements.push({ type: 'h4', text: line.substring(5).trim() });
        }
        // Handle lists
        else if (line.match(/^[\-\*]\s+/) || line.match(/^\d+\.\s+/)) {
            inList = true;
            listItems.push(line.replace(/^[\-\*]\s+/, '').replace(/^\d+\.\s+/, '').trim());
        }
        // Handle horizontal rule
        else if (line.trim() === '---') {
            if (inList) {
                elements.push({ type: 'list', items: listItems });
                listItems = [];
                inList = false;
            }
            elements.push({ type: 'hr' });
        }
        // Handle empty lines
        else if (line.trim() === '') {
            if (inList) {
                elements.push({ type: 'list', items: listItems });
                listItems = [];
                inList = false;
            }
            // Skip empty lines
        }
        // Handle paragraphs
        else {
            if (inList) {
                elements.push({ type: 'list', items: listItems });
                listItems = [];
                inList = false;
            }
            elements.push({ type: 'paragraph', text: line.trim() });
        }
    }

    if (inList) {
        elements.push({ type: 'list', items: listItems });
    }

    return elements;
}

// Parse bold and italic text
function parseInlineFormatting(text) {
    const runs = [];
    let currentPos = 0;

    // Match **bold**, *italic*, `code`, etc.
    const regex = /(\*\*[^\*]+\*\*|\*[^\*]+\*|`[^`]+`)/g;
    let match;

    while ((match = regex.exec(text)) !== null) {
        // Add text before match
        if (match.index > currentPos) {
            runs.push(new TextRun(text.substring(currentPos, match.index)));
        }

        const matched = match[0];
        if (matched.startsWith('**') && matched.endsWith('**')) {
            runs.push(new TextRun({ text: matched.slice(2, -2), bold: true }));
        } else if (matched.startsWith('*') && matched.endsWith('*')) {
            runs.push(new TextRun({ text: matched.slice(1, -1), italics: true }));
        } else if (matched.startsWith('`') && matched.endsWith('`')) {
            runs.push(new TextRun({
                text: matched.slice(1, -1),
                font: "Courier New",
                color: "E74C3C",
                size: 20
            }));
        }

        currentPos = match.index + matched.length;
    }

    // Add remaining text
    if (currentPos < text.length) {
        runs.push(new TextRun(text.substring(currentPos)));
    }

    return runs.length > 0 ? runs : [new TextRun(text)];
}

// Convert parsed elements to docx elements
function createDocxElements(elements) {
    const docxElements = [];

    elements.forEach(element => {
        switch (element.type) {
            case 'h1':
                docxElements.push(new Paragraph({
                    heading: HeadingLevel.HEADING_1,
                    children: parseInlineFormatting(element.text),
                    spacing: { before: 400, after: 200 }
                }));
                break;

            case 'h2':
                docxElements.push(new Paragraph({
                    heading: HeadingLevel.HEADING_2,
                    children: parseInlineFormatting(element.text),
                    spacing: { before: 300, after: 150 }
                }));
                break;

            case 'h3':
                docxElements.push(new Paragraph({
                    heading: HeadingLevel.HEADING_3,
                    children: parseInlineFormatting(element.text),
                    spacing: { before: 240, after: 120 }
                }));
                break;

            case 'h4':
                docxElements.push(new Paragraph({
                    heading: HeadingLevel.HEADING_4,
                    children: parseInlineFormatting(element.text),
                    spacing: { before: 200, after: 100 }
                }));
                break;

            case 'paragraph':
                if (element.text.length > 0) {
                    docxElements.push(new Paragraph({
                        children: parseInlineFormatting(element.text),
                        spacing: { after: 120 }
                    }));
                }
                break;

            case 'list':
                element.items.forEach(item => {
                    docxElements.push(new Paragraph({
                        numbering: { reference: "bullet-list", level: 0 },
                        children: parseInlineFormatting(item),
                        spacing: { after: 60 }
                    }));
                });
                break;

            case 'code':
                docxElements.push(new Paragraph({
                    children: [new TextRun({
                        text: element.content,
                        font: "Courier New",
                        size: 18
                    })],
                    spacing: { before: 120, after: 120 },
                    shading: { fill: "F5F5F5" }
                }));
                break;

            case 'hr':
                docxElements.push(new Paragraph({
                    children: [new TextRun("")],
                    spacing: { before: 200, after: 200 },
                    border: { bottom: { color: "CCCCCC", space: 1, style: BorderStyle.SINGLE, size: 6 } }
                }));
                break;
        }
    });

    return docxElements;
}

// Parse markdown
const elements = parseMarkdown(mdContent);

// Create document
const doc = new Document({
    styles: {
        default: {
            document: {
                run: { font: "Arial", size: 22 }
            }
        },
        paragraphStyles: [
            {
                id: "Heading1",
                name: "Heading 1",
                basedOn: "Normal",
                next: "Normal",
                quickFormat: true,
                run: { size: 32, bold: true, color: "277884", font: "Arial" },
                paragraph: { spacing: { before: 400, after: 200 }, outlineLevel: 0 }
            },
            {
                id: "Heading2",
                name: "Heading 2",
                basedOn: "Normal",
                next: "Normal",
                quickFormat: true,
                run: { size: 28, bold: true, color: "277884", font: "Arial" },
                paragraph: { spacing: { before: 300, after: 150 }, outlineLevel: 1 }
            },
            {
                id: "Heading3",
                name: "Heading 3",
                basedOn: "Normal",
                next: "Normal",
                quickFormat: true,
                run: { size: 24, bold: true, color: "2C2C2C", font: "Arial" },
                paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 2 }
            },
            {
                id: "Heading4",
                name: "Heading 4",
                basedOn: "Normal",
                next: "Normal",
                quickFormat: true,
                run: { size: 22, bold: true, color: "2C2C2C", font: "Arial" },
                paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 3 }
            }
        ]
    },
    numbering: {
        config: [
            {
                reference: "bullet-list",
                levels: [
                    {
                        level: 0,
                        format: LevelFormat.BULLET,
                        text: "•",
                        alignment: AlignmentType.LEFT,
                        style: {
                            paragraph: {
                                indent: { left: 720, hanging: 360 }
                            }
                        }
                    }
                ]
            }
        ]
    },
    sections: [{
        properties: {
            page: {
                margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 }
            }
        },
        children: createDocxElements(elements)
    }]
});

// Save document
Packer.toBuffer(doc).then(buffer => {
    fs.writeFileSync('/Users/admin/workspace/troubleshooting-tools/docs/publish/network-troubleshooting-tools-demo-report.docx', buffer);
    console.log('Document created successfully!');
});
