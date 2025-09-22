#!/usr/bin/env python3
"""
Improved Test Case Generator
Supports flexible parameter expansion and automatic variable resolution
"""

import argparse
import json
import yaml
import os
import sys
import re
from datetime import datetime
from pathlib import Path
from itertools import product


class ImprovedTestCaseGenerator:
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

    def extract_template_variables(self, template):
        """Extract all variables from template string"""
        return set(re.findall(r'\{(\w+)\}', template))

    def resolve_variables(self, template, variables, category):
        """Resolve all variables in template string with smart optional parameter handling"""
        resolved = template

        # Get category-specific variables
        env_vars = self.spec_config['variables'].get(category, {})

        # First, handle optional parameters - remove options for missing variables
        import re

        # Find all option patterns like "--option {variable}"
        option_pattern = r'--(\w+)\s+\{(\w+)\}'
        matches = re.findall(option_pattern, resolved)

        for option_name, var_name in matches:
            # Check if variable exists in either variables dict or env_vars dict
            if var_name not in variables and var_name not in env_vars:
                # Remove this entire option if the variable is missing
                option_full_pattern = r'--' + option_name + r'\s+\{' + var_name + r'\}'
                resolved = re.sub(option_full_pattern, '', resolved)

        # Clean up extra spaces
        resolved = re.sub(r'\s+', ' ', resolved).strip()

        # Replace additional variables
        for var_name, var_value in variables.items():
            resolved = resolved.replace(f"{{{var_name}}}", str(var_value))

        # Recursively resolve environment variables (support nested variables)
        max_iterations = 5  # Prevent infinite loop
        for i in range(max_iterations):
            old_resolved = resolved
            for var_name, var_value in env_vars.items():
                resolved = resolved.replace(f"{{{var_name}}}", str(var_value))
            if resolved == old_resolved:
                break  # No more changes

        return resolved

    def get_script_path(self, category, tool):
        """Get complete script path: topic_dir + tool_dir + script_name"""
        # Get topic configuration from test_config
        topic_config = None
        for topic_name, config in self.test_config.get('topics', {}).items():
            if topic_name == category:
                topic_config = config
                break

        if not topic_config:
            raise ValueError(f"Topic '{category}' not found in test config")

        # Get topic directory (first entry in dirs list)
        topic_dirs = topic_config.get('dirs', [])
        if not topic_dirs:
            raise ValueError(f"No dirs specified for topic '{category}'")

        topic_dir = topic_dirs[0]  # Use first directory as base

        # Get tool directory and script name
        tool_dir = tool.get('dir', '')
        script_name = tool.get('script', '')

        # Construct complete path: topic_dir/tool_dir/script_name
        if tool_dir:
            return f"{topic_dir}/{tool_dir}/{script_name}"
        else:
            return f"{topic_dir}/{script_name}"

    def generate_parameter_combinations(self, tool, filtered_directions):
        """Generate all parameter combinations for a tool with conditional support"""
        # Check if tool template uses direction-specific variables
        template = tool.get('template', '')
        uses_direction_vars = any(var in template for var in ['{SRC_IP}', '{DST_IP}', '{direction}'])

        # Extract all parameters that need expansion
        expandable_params = {}

        # Add protocols if defined (backward compatibility)
        if 'protocols' in tool:
            expandable_params['protocol'] = tool['protocols']

        # Handle conditional parameters
        if 'parameters' in tool:
            parameters = tool['parameters']

            # Check if any parameter has conditional values (dict format)
            conditional_params = {}
            simple_params = {}

            for param_name, param_values in parameters.items():
                if isinstance(param_values, dict):
                    # This is a conditional parameter
                    conditional_params[param_name] = param_values
                else:
                    # This is a simple list parameter
                    simple_params[param_name] = param_values

            if conditional_params:
                return self._generate_conditional_combinations(simple_params, conditional_params, filtered_directions, uses_direction_vars)
            else:
                expandable_params.update(simple_params)

        # Only add directions if the tool actually uses direction-specific variables
        if filtered_directions and uses_direction_vars:
            expandable_params['direction'] = list(filtered_directions.keys())

        # Generate all combinations for simple parameters
        if not expandable_params:
            return [{}]

        param_names = list(expandable_params.keys())
        param_values = [expandable_params[name] for name in param_names]

        combinations = []
        for combination in product(*param_values):
            param_dict = dict(zip(param_names, combination))
            combinations.append(param_dict)

        return combinations

    def _generate_conditional_combinations(self, simple_params, conditional_params, directions, uses_direction_vars):
        """Generate combinations with conditional parameter dependencies"""
        combinations = []

        # Only add directions to simple params if tool actually uses direction variables
        if directions and uses_direction_vars:
            simple_params['direction'] = list(directions.keys())

        # Generate base combinations from simple parameters
        if simple_params:
            simple_names = list(simple_params.keys())
            simple_values = [simple_params[name] for name in simple_names]
            base_combinations = [dict(zip(simple_names, combo)) for combo in product(*simple_values)]
        else:
            base_combinations = [{}]

        # Process conditional parameters - handle nested structure
        for cond_param_name, cond_param_rules in conditional_params.items():
            new_combinations = []

            # For each condition value (e.g., "data", "control")
            for condition_value, sub_params in cond_param_rules.items():
                # Create combination with the main parameter
                main_combo = {cond_param_name: condition_value}

                if sub_params:
                    # This condition has sub-parameters (e.g., data -> subcategory)
                    for sub_param_name, sub_param_values in sub_params.items():
                        for sub_value in sub_param_values:
                            combo = main_combo.copy()
                            combo[sub_param_name] = sub_value
                            new_combinations.append(combo)
                else:
                    # This condition has no sub-parameters (e.g., control)
                    new_combinations.append(main_combo)

            # Combine with base combinations
            final_combinations = []
            for base_combo in base_combinations:
                for cond_combo in new_combinations:
                    final_combo = base_combo.copy()
                    final_combo.update(cond_combo)
                    final_combinations.append(final_combo)

            base_combinations = final_combinations

        return base_combinations


    def generate_case_name(self, script, param_dict):
        """Generate test case name based on script and parameters"""
        # Remove .py extension and path prefixes
        base_name = script.replace('.py', '').replace('/', '_').replace('-', '_')

        # Add parameters to name
        param_parts = []
        for key, value in param_dict.items():
            if key != 'direction':  # direction is handled specially
                # Clean up parameter value: remove spaces, special chars
                clean_value = str(value).replace(' ', '_').replace('-', '_').replace('--', '').strip('_')
                if clean_value:  # Only add non-empty values
                    param_parts.append(f"{key}_{clean_value}")

        if 'direction' in param_dict:
            param_parts.insert(0, param_dict['direction'])

        if param_parts:
            return f"{base_name}_{'_'.join(param_parts)}"
        else:
            return base_name

    def generate_test_cases_for_category(self, category):
        """Generate test cases for a specific category"""
        if category not in self.spec_config['test_matrix']:
            print(f"Warning: Category '{category}' not found in spec config")
            return

        matrix = self.spec_config['test_matrix'][category]
        tools = matrix.get('tools', [])
        directions = matrix.get('directions', {})

        # Get category-specific duration
        category_duration = matrix.get('duration', self.spec_config['defaults'].get('duration', 8))

        # Generate cases for each tool
        for tool in tools:

            # Check if tool specifies specific directions to generate
            tool_directions = tool.get('directions', None)
            if tool_directions:
                # Filter directions based on tool specification
                if isinstance(tool_directions, list):
                    filtered_directions = {k: v for k, v in directions.items() if k in tool_directions}
                else:
                    # Single direction specified
                    filtered_directions = {tool_directions: directions.get(tool_directions, {})}
            else:
                # Use all directions
                filtered_directions = directions

            # Generate all parameter combinations
            param_combinations = self.generate_parameter_combinations(tool, filtered_directions)

            # If no combinations found, create a single case with empty params
            if not param_combinations:
                param_combinations = [{}]

            for param_dict in param_combinations:
                # Use the tool's template
                template = tool.get('template', '')

                # Prepare variables for template resolution
                variables = {
                    'path': self.get_script_path(category, tool),
                }

                # Add parameter values
                variables.update(param_dict)

                # Add direction-specific variables if direction is specified
                if 'direction' in param_dict and param_dict['direction'] in filtered_directions:
                    direction_vars = filtered_directions[param_dict['direction']]
                    variables.update(direction_vars)

                # Resolve template
                command = self.resolve_variables(template, variables, category)

                # Generate case name
                case_name = self.generate_case_name(tool.get('script', ''), param_dict)

                # Create test case
                test_case = {
                    "id": self.case_id_counter,
                    "name": case_name,
                    "command": command,
                    "duration": category_duration
                }

                self.test_cases.append(test_case)
                self.case_id_counter += 1

    def generate_summary(self):
        """Generate test case summary"""
        summary = {
            "total_cases": len(self.test_cases),
            "tools": {},
            "parameters": {}
        }

        # Count by tools and parameters
        for case in self.test_cases:
            # Extract tool name
            tool_name = case['name'].split('_')[0] if '_' in case['name'] else case['name']
            summary["tools"][tool_name] = summary["tools"].get(tool_name, 0) + 1

            # Count parameter combinations
            if 'parameters' in case:
                param_key = str(sorted(case['parameters'].items()))
                summary["parameters"][param_key] = summary["parameters"].get(param_key, 0) + 1

        return summary

    def generate(self):
        """Generate all test cases"""
        # Use all categories from spec_config test_matrix
        categories = list(self.spec_config['test_matrix'].keys())

        if not categories:
            print("Warning: No categories found in spec config")
            return None

        # Generate test cases for each category
        for category in categories:
            print(f"Generating test cases for category: {category}")
            self.generate_test_cases_for_category(category)

        # Generate summary
        summary = self.generate_summary()

        # Prepare output data
        output_data = {
            "metadata": {
                "description": self.spec_config['metadata']['description'],
                "source": f"Generated from spec config: {self.spec_config['metadata']['name']}",
                "total_cases": len(self.test_cases),
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "test_cases": self.test_cases,
            "summary": summary
        }

        return output_data


def main():
    parser = argparse.ArgumentParser(description="Generate test cases from spec configuration (Improved)")
    parser.add_argument("--test-config", required=True, help="Path to test configuration YAML file")
    parser.add_argument("--spec-config", required=True, help="Path to spec configuration YAML file")
    parser.add_argument("--output", required=True, help="Output path for generated JSON file")
    parser.add_argument("--compare", help="Compare with existing test cases file")

    args = parser.parse_args()

    # Generate test cases
    generator = ImprovedTestCaseGenerator(args.test_config, args.spec_config)
    output_data = generator.generate()

    # Save to file
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    # Display summary
    print("\n=== Improved Test Case Generator ===")
    print(f"Spec config: {generator.spec_config['metadata']['name']}")
    print(f"Version: {generator.spec_config['metadata']['version']}")
    print(f"Generated {len(generator.test_cases)} test cases")
    print(f"Test cases saved to: {args.output}")

    print(f"\n=== Generation Summary ===")
    print(f"Total cases: {len(generator.test_cases)}")

    if output_data and 'summary' in output_data:
        summary = output_data['summary']
        print(f"Tools: {len(summary['tools'])}")
        print(f"Parameter combinations: {len(summary['parameters'])}")
    else:
        print("No test cases generated")


if __name__ == "__main__":
    main()