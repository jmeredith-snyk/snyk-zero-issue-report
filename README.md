# Snyk Issue Reporter

A Python script that generates CSV reports of Snyk projects and their open issue counts. Supports both organization and group-level reporting.

## Disclaimer

This script is provided as an **example** of how to generate Snyk issue reports using the Snyk API. It is **not officially supported by Snyk** and is provided "as is" without any warranties. This script is intended for educational and demonstration purposes only.

**Important Notes:**
- This is an example implementation and may require modifications for your specific use case
- Snyk does not provide support for modifications to this script
- Use at your own risk and test thoroughly in your environment
- The script may need updates as the Snyk API evolves

## Features

- Summary reports with issue counts by severity
- Detailed reports with individual issue metadata
- Organization and group-level analysis
- Concurrent processing for improved performance
- CSV injection protection
- Interactive and command-line modes

## Prerequisites

- Python 3.7 or higher
- Snyk API token with appropriate permissions

## Installation

### Option 1: Automated Setup (Recommended)

Run the setup script to automatically configure your environment:

```bash
chmod +x setup.sh
./setup.sh
```

The setup script will:
- Check for Python 3 installation
- Create a virtual environment (`venv`)
- Install required dependencies (`requests`, `python-dotenv`)
- Create a `.env` template file
- Activate the virtual environment

### Option 2: Manual Setup

1. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install requests python-dotenv
   ```

3. **Create `.env` file**:
   ```bash
   touch .env
   ```

## Configuration

### Environment Variables

Create a `.env` file in the project root with your Snyk API token:

```bash
# Required: Your Snyk API token
SNYK_TOKEN="your_snyk_api_token_here"

# Optional: Multiple organization IDs (for interactive mode)
# SNYK_ORG_IDS="org-id-1,org-id-2,org-id-3"

# Optional: Multiple group IDs (for interactive mode)
# SNYK_GROUP_IDS="group-id-1,group-id-2,group-id-3"
```

### Getting Your Snyk API Token

1. **Log into Snyk**: Go to [https://app.snyk.io](https://app.snyk.io)
2. **Navigate to Account Settings**: Click your profile → Account Settings
3. **API Tokens**: Go to the "API tokens" section
4. **Create Token**: Click "Create Token" and give it a descriptive name
5. **Copy Token**: Copy the generated token to your `.env` file

### Example `.env` File

```bash
# Single organization setup
SNYK_TOKEN="abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"

# Multiple organizations (for interactive mode)
SNYK_TOKEN="abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
SNYK_ORG_IDS="org-abc123,org-def456,org-ghi789"

# Multiple groups (for interactive mode)
SNYK_TOKEN="abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
SNYK_GROUP_IDS="group-abc123,group-def456,group-ghi789"

# Mixed organizations and groups (for interactive mode)
SNYK_TOKEN="abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
SNYK_ORG_IDS="org-abc123,org-def456"
SNYK_GROUP_IDS="group-ghi789,group-jkl012"
```

## Usage

### Running the Script

**Option 1: Using the wrapper script (Recommended)**
```bash
./run.sh --org <org-id>
./run.sh --group <group-id>
./run.sh --help
```

**Option 2: Activate virtual environment manually**
```bash
source venv/bin/activate
python3 snyk_issue_reporter.py --org <org-id>
```

**Option 3: Run directly through virtual environment**
```bash
./venv/bin/python snyk_issue_reporter.py --org <org-id>
```

### Command Line

**Organization Report**:
```bash
python3 snyk_issue_reporter.py --org <org-id>
```

**Group Report**:
```bash
python3 snyk_issue_reporter.py --group <group-id>
```

**Detailed Report**:
```bash
python3 snyk_issue_reporter.py --org <org-id> --detailed
```

**With Project Limit**:
```bash
python3 snyk_issue_reporter.py --org <org-id> --limit 10
```
*Note: `--limit` restricts the number of projects processed per organization, not the total number of issues.*

**With Custom Concurrency**:
```bash
python3 snyk_issue_reporter.py --group <group-id> --workers 12
```

**Debug Mode**:
```bash
python3 snyk_issue_reporter.py --org <org-id> --debug
```

### Interactive Mode

Run without arguments to use interactive mode:
```bash
python3 snyk_issue_reporter.py
```

Interactive mode allows you to:
- Select from multiple organizations and groups (if configured in `.env`)
- Choose between summary and detailed reports
- Select specific organizations or groups

## Output

The script generates CSV files with the following naming:
- `snyk_org_report_<org-id>_summary.csv`
- `snyk_org_report_<org-id>_detailed.csv`
- `snyk_group_report_<group-id>_summary.csv`
- `snyk_group_report_<group-id>_detailed.csv`

## Options

| Option | Description |
|--------|-------------|
| `--org ORG_ID` | Run report for a single organization |
| `--group GROUP_ID` | Run report for a single group |
| `--limit LIMIT` | Limit projects processed per organization (not total issues) |
| `--detailed` | Generate detailed report instead of summary |
| `--debug` | Enable debug logging |
| `--workers WORKERS` | Number of concurrent workers (default: 8) |

## Troubleshooting

**ModuleNotFoundError: No module named 'requests'**: 
This error occurs when running the script outside the virtual environment. The dependencies are installed in the virtual environment, not globally.

**Solution**: Use one of these methods:
```bash
# Option 1: Use the wrapper script (recommended)
./run.sh --org <org-id>

# Option 2: Activate virtual environment first
source venv/bin/activate
python3 snyk_issue_reporter.py --org <org-id>

# Option 3: Run directly through virtual environment
./venv/bin/python snyk_issue_reporter.py --org <org-id>
```

**If dependencies are missing**:
```bash
# Activate virtual environment first
source venv/bin/activate
# Then install dependencies
pip install requests python-dotenv
```

**API Authentication Errors**: 
- Verify your Snyk API token in `.env` file
- Check token permissions in Snyk account settings
- Ensure token hasn't expired

**No Projects Found**: 
- Check organization/group ID is correct
- Verify token has access to the specified organization/group
- Try running with `--debug` to see detailed API responses

**Permission Denied on setup.sh**:
```bash
chmod +x setup.sh
./setup.sh
```

**Performance Tips**:
- Use `--workers` to adjust concurrency (higher for faster processing, lower for stability)
- Use `--limit` to reduce data volume for testing
- Group reports benefit most from concurrent processing
- Built-in rate limiting prevents API throttling (100ms delay between calls)

For help: `python3 snyk_issue_reporter.py --help` 