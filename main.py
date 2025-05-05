#!/usr/bin/env python3

import argparse
import logging
import re
import pathlib
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Sanitizes a file by removing or redacting sensitive data patterns.")
    parser.add_argument("input_file", type=str, help="Path to the input file.")
    parser.add_argument("output_file", type=str, help="Path to the output file.")
    parser.add_argument(
        "--patterns",
        type=str,
        nargs="+",
        help="Regular expression patterns to sanitize.  Example: --patterns '[0-9]{16}' '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="Replace matched patterns with '[REDACTED]'. If not set, matches will be removed.",
    )
    parser.add_argument(
        "--log_level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)",
    )
    return parser.parse_args()


def sanitize_file(input_file, output_file, patterns, redact=False):
    """
    Sanitizes the input file by removing or redacting sensitive data patterns
    and writes the result to the output file.

    Args:
        input_file (str): Path to the input file.
        output_file (str): Path to the output file.
        patterns (list): List of regular expression patterns to sanitize.
        redact (bool): If True, replace matches with '[REDACTED]'. Otherwise, remove them.
    """
    try:
        # Input validation: Check if the input file exists
        input_path = pathlib.Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Input validation: Check if the input file is actually a file and not a directory, etc.
        if not input_path.is_file():
            raise ValueError(f"Input path is not a file: {input_file}")

        # Read the content of the input file
        with open(input_file, "r", encoding="utf-8") as f_in:
            content = f_in.read()

        # Sanitize the content based on the provided patterns
        for pattern in patterns:
            try:
                # Compile the regular expression pattern
                compiled_pattern = re.compile(pattern)

                # Sanitize the content using the compiled pattern
                if redact:
                    content = compiled_pattern.sub("[REDACTED]", content)
                else:
                    content = compiled_pattern.sub("", content)

                logging.debug(f"Successfully applied pattern: {pattern}")

            except re.error as e:
                logging.error(f"Invalid regular expression pattern: {pattern}. Error: {e}")
                raise ValueError(f"Invalid regular expression pattern: {pattern}") from e

        # Write the sanitized content to the output file
        with open(output_file, "w", encoding="utf-8") as f_out:
            f_out.write(content)

        logging.info(f"Successfully sanitized file: {input_file} -> {output_file}")

    except FileNotFoundError as e:
        logging.error(f"File not found error: {e}")
        raise
    except PermissionError as e:
        logging.error(f"Permission error: {e}")
        raise
    except OSError as e:
        logging.error(f"OS error: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def main():
    """
    Main function to execute the file sanitization process.
    """
    args = setup_argparse()

    # Set logging level from arguments
    logging.getLogger().setLevel(args.log_level)

    try:
        sanitize_file(args.input_file, args.output_file, args.patterns, args.redact)

    except Exception as e:
        logging.error(f"Sanitization process failed: {e}")
        exit(1)


if __name__ == "__main__":
    # Usage example:
    # python main.py input.txt output.txt --patterns '[0-9]{16}' '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' --redact
    # python main.py input.txt output.txt --patterns '[0-9]{9}' --log_level DEBUG
    main()