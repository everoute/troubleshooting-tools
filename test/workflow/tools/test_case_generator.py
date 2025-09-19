#!/usr/bin/env python3
"""
Test Case Generator
Generates structured JSON test cases from spec configuration files
"""

import argparse
import json
import yaml
import os
import sys
from datetime import datetime
from pathlib import Path


class TestCaseGenerator:
    def __init__(self, test_config_path, spec_config_path):
        self.test_config = self.load_yaml(test_config_path)
        self.spec_config = self.load_yaml(spec_config_path)
        self.test_cases = []
        self.case_id_counter = 1

    def load_yaml(self, file_path):
        """Load YAML configuration file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            sys.exit(1)

    def resolve_variables(self, template, variables, category):
        """Resolve all variables in template string"""
        resolved = template

        # Get category-specific variables
        env_vars = self.spec_config['variables'].get(category, {})

        # Replace additional variables first
        for var_name, var_value in variables.items():
            resolved = resolved.replace(f"{{{var_name}}}", var_value)

        # Recursively resolve environment variables (support nested variables)
        max_iterations = 5  # Prevent infinite loop
        for i in range(max_iterations):
            old_resolved = resolved
            for var_name, var_value in env_vars.items():
                resolved = resolved.replace(f"{{{var_name}}}", var_value)
            if resolved == old_resolved:
                break  # No more changes

        return resolved

    def generate_case_name(self, script, direction, protocol):
        """Generate test case name based on script, direction and protocol"""
        # Remove .py extension and add direction and protocol
        base_name = script.replace('.py', '')

        # Special case: ICMP tools don't include protocol suffix (only have icmp)
        if 'icmp' in script and protocol == 'icmp':
            return f"{base_name}_{direction}"
        else:
            return f"{base_name}_{direction}_{protocol}"

    def get_script_path(self, category, script):
        """Get relative script path based on category and test config"""
        if category == "system-network":
            return f"ebpf-tools/performance/system-network/{script}"
        elif category == "vm-network":
            return f"ebpf-tools/performance/vm-network/{script}"
        else:
            return f"ebpf-tools/{script}"

    def generate_test_cases_for_category(self, category):
        """Generate test cases for a specific category"""
        if category not in self.spec_config['test_matrix']:
            print(f"Warning: Category '{category}' not found in spec config")
            return

        matrix = self.spec_config['test_matrix'][category]
        tools = matrix.get('tools', [])
        directions = matrix.get('directions', {})

        # Get category-specific duration (falls back to global default)
        category_duration = matrix.get('duration', self.spec_config['defaults'].get('duration', 8))

        # Generate cases for each tool
        for tool in tools:
            script = tool['script']
            template = tool['template']
            protocols = tool.get('protocols', ['tcp'])

            # Generate cases for each protocol
            for protocol in protocols:
                # Generate cases for each direction
                for direction, direction_vars in directions.items():
                    # Prepare variables for template resolution
                    variables = {
                        'path': self.get_script_path(category, script),
                        'direction': direction,
                        'protocol': protocol
                    }

                    # Add direction-specific variables
                    variables.update(direction_vars)

                    # Resolve template
                    command = self.resolve_variables(template, variables, category)

                    # Generate case name
                    case_name = self.generate_case_name(script, direction, protocol)

                    # Create test case
                    test_case = {
                        "id": self.case_id_counter,
                        "name": case_name,
                        "command": command,
                        "duration": category_duration
                    }

                    self.test_cases.append(test_case)
                    self.case_id_counter += 1

    def count_cases_by_category(self):
        """Count test cases by category for summary"""
        system_network_count = 0
        vm_network_count = 0

        for case in self.test_cases:
            if 'system_network_' in case['name']:
                system_network_count += 1
            elif 'vm_network_' in case['name']:
                vm_network_count += 1

        return system_network_count, vm_network_count

    def generate_summary(self):
        """Generate test case summary"""
        system_count, vm_count = self.count_cases_by_category()

        # Count by tool categories
        tool_counts = {}
        for case in self.test_cases:
            # Extract tool name (everything before the direction_protocol part)
            name_parts = case['name'].split('_')
            if len(name_parts) >= 3:
                # Reconstruct tool name (everything except last 2 parts which are direction_protocol)
                tool_name = '_'.join(name_parts[:-2])
                tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1

        summary = {
            "total_cases": len(self.test_cases),
            "system_network_cases": system_count,
            "vm_network_cases": vm_count,
            "categories": {
                "system_network": {},
                "vm_network": {}
            }
        }

        # Categorize tool counts
        for tool_name, count in tool_counts.items():
            if tool_name.startswith('system_network_'):
                summary["categories"]["system_network"][tool_name] = count
            elif tool_name.startswith('vm_network_'):
                summary["categories"]["vm_network"][tool_name] = count

        return summary

    def generate(self):
        """Generate all test cases"""
        print("=== Test Case Generator ===")
        print(f"Spec config: {self.spec_config['metadata']['name']}")
        print(f"Version: {self.spec_config['metadata']['version']}")

        # Generate test cases for each category in test matrix
        for category in self.spec_config['test_matrix'].keys():
            print(f"Generating test cases for category: {category}")
            self.generate_test_cases_for_category(category)

        print(f"Generated {len(self.test_cases)} test cases")

        # Generate output JSON structure
        output = {
            "metadata": {
                "description": self.spec_config['metadata']['description'],
                "source": f"Generated from spec config: {self.spec_config['metadata']['name']}",
                "total_cases": len(self.test_cases),
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "test_cases": self.test_cases,
            "summary": self.generate_summary()
        }

        return output

    def save_to_file(self, output_path, data):
        """Save generated test cases to JSON file"""
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            print(f"Test cases saved to: {output_path}")
            return True
        except Exception as e:
            print(f"Error saving to {output_path}: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='Generate test cases from spec configuration')
    parser.add_argument('--test-config', required=True, help='Path to test configuration YAML file')
    parser.add_argument('--spec-config', required=True, help='Path to spec configuration YAML file')
    parser.add_argument('--output', required=True, help='Output path for generated JSON file')
    parser.add_argument('--compare', help='Compare with existing test cases file')

    args = parser.parse_args()

    # Validate input files
    if not os.path.exists(args.test_config):
        print(f"Error: Test config file not found: {args.test_config}")
        sys.exit(1)

    if not os.path.exists(args.spec_config):
        print(f"Error: Spec config file not found: {args.spec_config}")
        sys.exit(1)

    # Generate test cases
    generator = TestCaseGenerator(args.test_config, args.spec_config)
    output_data = generator.generate()

    # Save to file
    if generator.save_to_file(args.output, output_data):
        print("\n=== Generation Summary ===")
        print(f"Total cases: {output_data['summary']['total_cases']}")
        print(f"System network cases: {output_data['summary']['system_network_cases']}")
        print(f"VM network cases: {output_data['summary']['vm_network_cases']}")

        # Compare with existing file if requested
        if args.compare and os.path.exists(args.compare):
            print(f"\n=== Comparing with {args.compare} ===")
            compare_test_cases(args.output, args.compare)
    else:
        sys.exit(1)


def compare_test_cases(generated_file, existing_file):
    """Compare generated test cases with existing ones"""
    try:
        with open(generated_file, 'r') as f:
            generated = json.load(f)
        with open(existing_file, 'r') as f:
            existing = json.load(f)

        gen_cases = generated['test_cases']
        exist_cases = existing['test_cases']

        print(f"Generated: {len(gen_cases)} cases")
        print(f"Existing: {len(exist_cases)} cases")

        # Compare case by case
        differences = []

        for i, (gen_case, exist_case) in enumerate(zip(gen_cases, exist_cases)):
            if gen_case['name'] != exist_case['name']:
                differences.append(f"Case {i+1} name: '{gen_case['name']}' vs '{exist_case['name']}'")
            if gen_case['command'] != exist_case['command']:
                differences.append(f"Case {i+1} command differs")
            if gen_case['duration'] != exist_case['duration']:
                differences.append(f"Case {i+1} duration: {gen_case['duration']} vs {exist_case['duration']}")

        if differences:
            print(f"Found {len(differences)} differences:")
            for diff in differences[:10]:  # Show first 10 differences
                print(f"  - {diff}")
            if len(differences) > 10:
                print(f"  ... and {len(differences) - 10} more")
        else:
            print("✅ All test cases match!")

    except Exception as e:
        print(f"Error comparing files: {e}")


if __name__ == "__main__":
    main()