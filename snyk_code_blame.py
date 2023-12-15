import json
import sys
import subprocess
import re
from collections import defaultdict

def get_git_blame_info(repo_path, file_path, line_number):
    """Get the author and date of a specific line in a file using git blame."""
    blame_output = subprocess.check_output(["git", "blame", "-L", f"{line_number},{line_number}", file_path], cwd=repo_path, text=True)
    # Extract the author and date from the blame output using regex
    match = re.search(r"\((.+?)\s+(\d{4}-\d{2}-\d{2})", blame_output)
    if match:
        author = match.group(1).strip()
        date = match.group(2)
    else:
        author = "Unknown"
        date = "Unknown"
    return author, date

def main(project_directory):
    # Run the Snyk code test and get the JSON output
    command = "snyk code test --json"
    process_result = subprocess.run(command.split(), cwd=project_directory, text=True, capture_output=True)
    
    # print("Output from snyk code test:")
    # print(process_result.stdout)
    # print("Errors (if any) from snyk code test:")
    # print(process_result.stderr)

    try:
        data = json.loads(process_result.stdout)
    except json.JSONDecodeError:
        print("Failed to decode JSON from snyk code test output.")
        sys.exit(1)

    # Dictionary to store issues by developer and severity
    issues_by_developer = defaultdict(lambda: defaultdict(int))

    # Iterate over the issues, find the author using git blame, and print the date
    for issue in data.get('runs', [{}])[0].get('results', []):
        file_path = issue['locations'][0]['physicalLocation']['artifactLocation']['uri']
        line_number = issue['locations'][0]['physicalLocation']['region']['startLine']
        author, date = get_git_blame_info(project_directory, file_path, line_number)
        severity = issue['level']
        issues_by_developer[author][severity] += 1
        print(f"Issue: {issue['message']['text']}")
        print(f"File: {file_path}, Line: {line_number}")
        print(f"The line was written by: {author} on {date}")
        print("--------------------------------------------------")

    # Print the summary table
    print("\nSummary of issues by developer and severity:")
    print("--------------------------------------------------")
    print("{:<25} {:<10} {:<10} {:<10}".format("Developer", "High", "Medium", "Low"))
    print("--------------------------------------------------")
    for developer, issues in issues_by_developer.items():
        print("{:<25} {:<10} {:<10} {:<10}".format(developer, issues.get('error', 0), issues.get('warning', 0), issues.get('note', 0)))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python snyk_blame.py /path/to/project_directory")
        sys.exit(1)

    project_directory = sys.argv[1]
    main(project_directory)