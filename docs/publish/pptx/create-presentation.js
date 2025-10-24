const pptxgen = require('pptxgenjs');
const html2pptx = require('/Users/admin/workspace/skills/document-skills/pptx/scripts/html2pptx.js');
const path = require('path');

async function createPresentation() {
    const pptx = new pptxgen();
    pptx.layout = 'LAYOUT_16x9';
    pptx.author = 'eBPF Network Troubleshooting Tools Team';
    pptx.title = 'eBPF 网络故障排查工具集介绍';

    const slideDir = '/Users/admin/workspace/troubleshooting-tools/docs/publish/pptx';

    // Slide 1: Cover
    await html2pptx(path.join(slideDir, 'slide01-cover.html'), pptx);

    // Slide 2: Agenda
    await html2pptx(path.join(slideDir, 'slide02-agenda.html'), pptx);

    // Slide 3: Problem Background
    await html2pptx(path.join(slideDir, 'slide03-problem-background.html'), pptx);

    // Slide 4: Typical Scenarios
    await html2pptx(path.join(slideDir, 'slide04-typical-scenarios.html'), pptx);

    // Slide 5: Design Goals
    await html2pptx(path.join(slideDir, 'slide05-design-goals.html'), pptx);

    // Slide 6: Tool Overview
    await html2pptx(path.join(slideDir, 'slide06-tool-overview.html'), pptx);

    // Slide 7: Tool Matrix (with table)
    const { slide: slide7, placeholders: placeholders7 } = await html2pptx(
        path.join(slideDir, 'slide07-tool-matrix.html'), pptx
    );

    // Add tool matrix table
    const matrixData = [
        // Header row
        [
            { text: "问题类型", options: { fill: { color: "277884" }, color: "FFFFFF", bold: true, fontSize: 13 } },
            { text: "Summary 工具", options: { fill: { color: "277884" }, color: "FFFFFF", bold: true, fontSize: 13 } },
            { text: "Details 工具", options: { fill: { color: "277884" }, color: "FFFFFF", bold: true, fontSize: 13 } },
            { text: "覆盖问题", options: { fill: { color: "277884" }, color: "FFFFFF", bold: true, fontSize: 13 } }
        ],
        // Data rows
        [
            { text: "丢包", options: { bold: true, fontSize: 12 } },
            "kernel_drop_stack_stats_summary_all.py",
            "eth_drop.py",
            "内核丢包位置、丢包原因分析"
        ],
        [
            { text: "延迟", options: { bold: true, fontSize: 12 } },
            "system/vm_network_latency_summary.py",
            "system/vm_network_latency_details.py",
            "分段延迟测量、长尾延迟识别"
        ],
        [
            { text: "OVS 性能", options: { bold: true, fontSize: 12 } },
            "ovs_upcall_latency_summary.py",
            "ovs_userspace_megaflow.py",
            "Upcall 延迟、流表未命中"
        ],
        [
            { text: "虚拟化", options: { bold: true, fontSize: 12 } },
            "vhost_eventfd_count.py",
            "vhost_queue_correlation_details.py",
            "vhost 队列、virtio 效率"
        ],
        [
            { text: "CPU/调度", options: { bold: true, fontSize: 12 } },
            "-",
            "offcputime-ts.py / pthread_rwlock_wrlock.bt",
            "Off-CPU 时间、锁竞争"
        ]
    ];

    slide7.addTable(matrixData, {
        ...placeholders7[0],
        colW: [1.5, 3.2, 3.5, 2.8],
        border: { pt: 1, color: "CCCCCC" },
        fontSize: 11,
        valign: "middle"
    });

    // Slide 8: Three Layer Model
    await html2pptx(path.join(slideDir, 'slide08-three-layer-model.html'), pptx);

    // Slide 9: Diagnosis Flow
    await html2pptx(path.join(slideDir, 'slide09-diagnosis-flow.html'), pptx);

    // Slide 10: Case 1 Overview
    await html2pptx(path.join(slideDir, 'slide10-case1-overview.html'), pptx);

    // Slide 11: Case 1 Diagnosis
    await html2pptx(path.join(slideDir, 'slide11-case1-diagnosis.html'), pptx);

    // Slide 12: Case 2 Overview
    await html2pptx(path.join(slideDir, 'slide12-case2-overview.html'), pptx);

    // Slide 13: Case 2 Diagnosis
    await html2pptx(path.join(slideDir, 'slide13-case2-diagnosis.html'), pptx);

    // Slide 14: Performance Summary
    await html2pptx(path.join(slideDir, 'slide14-performance-summary.html'), pptx);

    // Slide 15: Demo Scenarios
    await html2pptx(path.join(slideDir, 'slide15-demo-scenarios.html'), pptx);

    // Slide 16: Key Achievements
    await html2pptx(path.join(slideDir, 'slide16-key-achievements.html'), pptx);

    // Slide 17: Value Proposition
    await html2pptx(path.join(slideDir, 'slide17-value-proposition.html'), pptx);

    // Slide 18: Thank You
    await html2pptx(path.join(slideDir, 'slide18-thank-you.html'), pptx);

    // Save presentation
    const outputPath = path.join(slideDir, 'network-troubleshooting-tools-demo.pptx');
    await pptx.writeFile({ fileName: outputPath });
    console.log('Presentation created successfully:', outputPath);
}

createPresentation().catch(console.error);
