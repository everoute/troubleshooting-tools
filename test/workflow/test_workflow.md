1. 根据测试目标以及测试环境信息，编写 workflow/spec/<topic>-test-spec.yaml && workflow/config/<topic>-test-config.yaml;
2. 使用 test_case_generator.py 生成 workflow/case/<topic>-test-cases.json
3. 使用 test_runner.py 运行指定 topic && id 或全部的测试