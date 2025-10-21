#!/usr/bin/env python3
"""Main execution script for automated performance testing"""

import sys
import os
import logging
import argparse
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from core.ssh_manager import SSHManager
from core.remote_path_manager import RemotePathManager
from core.workflow_generator import EBPFCentricWorkflowGenerator
from core.test_executor import TestExecutor
from utils.config_loader import ConfigLoader
from utils.testcase_loader import TestcaseLoader


def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(f'automation_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        ]
    )


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Automated eBPF Performance Testing')
    parser.add_argument('--config-dir', default='../config',
                       help='Configuration directory path')
    parser.add_argument('--log-level', default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Logging level')
    parser.add_argument('--dry-run', action='store_true',
                       help='Generate workflow without executing')
    parser.add_argument('--workflow-output', default='generated_workflow.json',
                       help='Output file for generated workflow')
    parser.add_argument('--tools', nargs='+',
                       help='Specific tools to test (default: all)')
    parser.add_argument('--environments', nargs='+',
                       help='Specific environments to test (default: all)')

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    try:
        # Get absolute config directory path
        config_dir = os.path.abspath(args.config_dir)
        logger.info(f"Loading configurations from: {config_dir}")

        # Load configurations
        config_loader = ConfigLoader(config_dir)
        configs = config_loader.load_all_configs()

        # Validate configurations
        for config_type, config in configs.items():
            if not config_loader.validate_config(config_type, config):
                logger.error(f"Invalid {config_type} configuration")
                return 1

        logger.info("All configurations loaded and validated successfully")

        # Filter configurations based on arguments
        if args.tools:
            filtered_tools = {k: v for k, v in configs['ebpf']['ebpf_tools'].items()
                            if v['id'] in args.tools}
            configs['ebpf']['ebpf_tools'] = filtered_tools
            logger.info(f"Filtered to tools: {args.tools}")

        if args.environments:
            filtered_envs = {k: v for k, v in configs['env']['test_environments'].items()
                           if k in args.environments}
            configs['env']['test_environments'] = filtered_envs
            logger.info(f"Filtered to environments: {args.environments}")

        # Initialize testcase loader - auto-detect base path
        # Go up from test/automate-performance-test/scripts/ to repo root
        script_dir = os.path.dirname(os.path.dirname(__file__))  # test/automate-performance-test
        base_path = os.path.dirname(os.path.dirname(script_dir))  # repo root
        logger.info(f"Auto-detected base path: {base_path}")
        testcase_loader = TestcaseLoader(base_path)

        # Generate workflow with testcase loader
        logger.info("Generating test workflow...")
        workflow_generator = EBPFCentricWorkflowGenerator(
            testcase_loader=testcase_loader,
            base_path=base_path
        )
        workflow_spec = workflow_generator.generate_workflow_spec(
            configs['ssh'], configs['env'], configs['perf'], configs['ebpf']
        )

        # Validate workflow
        if not workflow_generator.validate_workflow(workflow_spec):
            logger.error("Generated workflow is invalid")
            return 1

        # Export workflow
        workflow_generator.export_workflow(workflow_spec, args.workflow_output)
        logger.info(f"Workflow exported to: {args.workflow_output}")

        if args.dry_run:
            logger.info("Dry run completed - workflow generated but not executed")
            return 0

        # Execute workflow
        logger.info("Starting workflow execution...")

        # Initialize managers
        ssh_manager = SSHManager(configs['ssh'])

        # Get workdir from first available host
        first_host = list(configs['ssh']['ssh_hosts'].keys())[0]
        workdir = configs['ssh']['ssh_hosts'][first_host]['workdir']
        path_manager = RemotePathManager(workdir)

        # Initialize test executor with full config
        test_executor = TestExecutor(ssh_manager, path_manager, configs)

        # Execute workflow
        with ssh_manager:
            execution_results = test_executor.execute_workflow(workflow_spec)

        # Log results
        logger.info(f"Workflow execution completed with status: {execution_results['status']}")
        if execution_results['status'] == 'failed':
            logger.error(f"Execution error: {execution_results.get('error', 'Unknown error')}")
            return 1

        # Summary
        total_cycles = len(execution_results['test_cycles'])
        successful_cycles = sum(1 for cycle in execution_results['test_cycles']
                              if cycle['status'] == 'completed')

        logger.info(f"Execution Summary:")
        logger.info(f"  Total test cycles: {total_cycles}")
        logger.info(f"  Successful cycles: {successful_cycles}")
        logger.info(f"  Failed cycles: {total_cycles - successful_cycles}")
        logger.info(f"  Start time: {execution_results['start_time']}")
        logger.info(f"  End time: {execution_results['end_time']}")

        return 0 if successful_cycles == total_cycles else 1

    except KeyboardInterrupt:
        logger.info("Execution interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())