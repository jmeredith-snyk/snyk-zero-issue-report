#!/usr/bin/env python3
"""
Snyk Issue Reporter

Generates CSV reports of Snyk projects and their open issue counts.
Supports both organization and group-level reporting.

Usage:
  python3 snyk_issue_reporter.py --org <org-id>
  python3 snyk_issue_reporter.py --group <group-id>
  python3 snyk_issue_reporter.py --org <org-id> --detailed
  python3 snyk_issue_reporter.py --help

Dependencies:
  pip install requests python-dotenv

Configuration:
  Create a .env file with: SNYK_TOKEN="your_snyk_api_token_here"
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os
import csv
import sys
import argparse
import logging
import concurrent.futures
import time
from dotenv import load_dotenv

# --- Global Configuration ---
# Load environment variables from .env file
load_dotenv()

# Snyk API configuration
API_VERSION = "2024-08-04"  # API version for Snyk REST API
API_BASE_URL = "https://api.snyk.io/rest"

# Set up logging
log = logging.getLogger(__name__)

# Defines the sorting order for severities in reports (critical first).
# Used for sorting detailed reports by severity level
SEVERITY_MAP = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

# Performance configuration
MAX_WORKERS = 8  # Number of concurrent API calls (increased for better performance)
BATCH_SIZE = 5   # Number of organizations to process in parallel (reduced for stability)

# --- Snyk API Client ---
class SnykClient:
    """
    A client for interacting with the Snyk REST API.
    
    This class handles all API communication with Snyk, including:
    - Authentication via API token
    - Automatic retries with exponential backoff for rate limiting and server errors
    - Pagination handling for large datasets
    - Error handling and logging
    - Data retrieval for groups, organizations, projects, and issues
    """
    
    def __init__(self, snyk_token, timeout=60):
        """
        Initialize the Snyk API client.
        
        Args:
            snyk_token (str): Snyk API token for authentication
            timeout (int): Request timeout in seconds (default: 60)
        
        Raises:
            ValueError: If snyk_token is not provided
        """
        if not snyk_token:
            raise ValueError("Snyk token is required.")
        
        self.timeout = timeout
        self.session = self._create_session(snyk_token)

    def _create_session(self, snyk_token):
        """
        Creates a requests.Session with retry logic and default headers.

        This setup provides resilience against transient network issues,
        server-side errors (5xx), and rate limiting (429).

        Args:
            snyk_token (str): The Snyk API token.

        Returns:
            requests.Session: A configured session object.
        """
        session = requests.Session()

        # Define the retry strategy
        retry_strategy = Retry(
            total=5,  # Total number of retries
            backoff_factor=1,  # Factor for exponential backoff (e.g., 1s, 2s, 4s, ...)
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
            allowed_methods=["GET"] # Only retry on GET requests
        )

        # Mount the retry strategy to an HTTP adapter
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # Set default headers for the session
        session.headers.update({
            "Authorization": f"token {snyk_token}",
            "Accept": "application/vnd.api+json"
        })

        return session

    def _request(self, method, url, params=None):
        """
        Makes an API request using the configured session.

        Args:
            method (str): HTTP method (e.g., 'GET')
            url (str): The API endpoint URL
            params (dict, optional): Query parameters for the request

        Returns:
            requests.Response: The response object

        Raises:
            requests.exceptions.RequestException: For connection errors or if retries fail.
            SystemExit: For critical, non-retriable errors like 401/403.
        """
        try:
            response = self.session.request(method, url, params=params, timeout=self.timeout)
            response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
            return response
        except requests.exceptions.HTTPError as e:
            # Handle specific, non-retriable HTTP errors
            if e.response.status_code in [401, 403]:
                log.error(f"Authentication failed (HTTP {e.response.status_code}). Please check your SNYK_TOKEN.")
            elif e.response.status_code == 404:
                log.error(f"Resource not found (HTTP 404) at {url}. Check the provided ID.")
            else:
                # For other HTTP errors, log the details
                error_details = e.response.text.replace('\n', ' ').replace('\r', '')
                log.error(f"HTTP Error {e.response.status_code} for {url}: {error_details}")
            # Exit for critical errors that shouldn't proceed
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            # Handle other request exceptions (e.g., network issues)
            log.error(f"API request failed for {url}: {e}")
            raise  # Re-raise the exception to be handled by the caller

    def _get_paginated_data(self, url, params=None):
        """
        Handles pagination for Snyk API GET requests using the session's retry logic.
        
        The Snyk API uses pagination for large datasets. This method automatically
        follows the 'next' links to retrieve all available data.
        
        Args:
            url (str): The API endpoint URL
            params (dict, optional): Query parameters for the request
            
        Returns:
            list: All items from all pages combined, or an empty list on failure.
        """
        items = []
        current_url = url
        current_params = params.copy() if params else {}

        while current_url:
            log.debug(f"Fetching page from {current_url} with params: {current_params}")
            try:
                response = self._request("GET", current_url, params=current_params)
                data = response.json()
                
                page_items = data.get("data", [])
                items.extend(page_items)
                log.debug(f"  -> Found {len(page_items)} items on this page. Total items: {len(items)}")
                
                # Check for the next page link
                next_link = data.get("links", {}).get("next")
                if next_link:
                    # The 'next' link is a full path, so we construct the full URL
                    current_url = f"https://api.snyk.io{next_link}"
                    current_params = {}  # Subsequent requests use the full URL from 'next' link
                else:
                    current_url = None  # No more pages
                    
            except requests.exceptions.RequestException:
                # Error is already logged in _request, just return what we have
                log.error(f"Stopping pagination for {url} due to previous errors.")
                return items  # Return partial data or an empty list
        return items

    def get_name(self, entity_type, entity_id):
        """
        Fetches the name of a group or an organization.
        
        Args:
            entity_type (str): Type of entity ('groups' or 'orgs')
            entity_id (str): ID of the entity to fetch
            
        Returns:
            str: The name of the entity, or "Unknown Name" if not found.
        """
        url = f"{API_BASE_URL}/{entity_type}/{entity_id}"
        params = {"version": API_VERSION}
        try:
            response = self._request("GET", url, params=params)
            return response.json().get("data", {}).get("attributes", {}).get("name", "Unknown Name")
        except requests.exceptions.RequestException:
            # Error is already logged in _request, return a default value
            log.warning(f"Could not fetch name for {entity_type} ID {entity_id}, continuing with 'Unknown Name'.")
            return "Unknown Name"

    def get_orgs_in_group(self, group_id):
        """
        Fetches all organizations within a group.
        
        Args:
            group_id (str): The Snyk Group ID
            
        Returns:
            list: List of tuples (org_id, org_name) for all organizations in the group
        """
        url = f"{API_BASE_URL}/groups/{group_id}/orgs"
        params = {"version": API_VERSION, "limit": 100}
        orgs_data = self._get_paginated_data(url, params)
        return [(org.get("id"), org.get("attributes", {}).get("name")) for org in orgs_data]

    def get_projects_in_org(self, org_id, limit=None):
        """
        Fetches projects for a single organization.
        
        Args:
            org_id (str): The Snyk Organization ID
            limit (int, optional): Maximum number of projects to return
            
        Returns:
            list: List of tuples (project_id, project_name) for all projects in the org
        """
        url = f"{API_BASE_URL}/orgs/{org_id}/projects"
        params = {"version": API_VERSION, "limit": 100}
        projects_data = self._get_paginated_data(url, params)
        projects = [(p.get("id"), p.get("attributes", {}).get("name")) for p in projects_data]
        return projects[:limit] if limit else projects

    def get_issues_in_org(self, org_id, project_ids=None):
        """
        Fetches raw issue data for a single organization.
        
        This method retrieves all types of issues: vulnerabilities, license issues,
        infrastructure as code issues, code issues, and container issues.
        
        Args:
            org_id (str): The Snyk Organization ID
            project_ids (list, optional): List of project IDs to filter issues for
            
        Returns:
            list: Raw issue data from the Snyk API
        """
        url = f"{API_BASE_URL}/orgs/{org_id}/issues"
        params = {
            "version": API_VERSION,
            "limit": 100,
            "types": "vuln,license,iac,code,container"  # All issue types
        }
        
        all_issues = self._get_paginated_data(url, params)
        
        # If project_ids is provided, filter issues to only those projects
        if project_ids:
            filtered_issues = []
            for issue in all_issues:
                scan_item = issue.get("relationships", {}).get("scan_item", {}).get("data", {})
                if scan_item and scan_item.get("type") == "project":
                    project_id = scan_item.get("id")
                    if project_id in project_ids:
                        filtered_issues.append(issue)
            return filtered_issues
        
        return all_issues

    def process_organization_concurrent(self, org_data, limit=None, detailed=False):
        """
        Process a single organization with all its data fetching.
        Designed for concurrent execution.
        
        Args:
            org_data (tuple): (org_id, org_name) tuple
            limit (int, optional): Project limit
            detailed (bool): Whether to generate detailed report
            
        Returns:
            list: Report data for this organization
        """
        org_id, org_name = org_data
        
        try:
            # Fetch projects first
            projects = self.get_projects_in_org(org_id, limit)
            
            if not projects:
                log.warning(f"No projects found for organization: {org_name}")
                return []
            
            # Extract project IDs for filtering
            project_ids = [pid for pid, pname in projects]
            
            # Fetch issues for only the selected projects
            all_issues = self.get_issues_in_org(org_id, project_ids)
            
            log.debug(f"Processing {len(projects)} projects for {org_name} (found {len(all_issues)} issues)")
            
            # Generate report data for this organization
            return generate_report_data(projects, all_issues, detailed, org_name)
            
        except Exception as e:
            log.error(f"Error processing organization {org_name} ({org_id}): {e}")
            return []

# --- Helper Functions ---
def get_snyk_token():
    """
    Gets Snyk token from .env or user prompt.
    
    This function first checks for a SNYK_TOKEN environment variable,
    and if not found, prompts the user to enter their token.
    
    Returns:
        str: The Snyk API token
        
    Exits:
        If no token is provided by the user
    """
    snyk_token = os.getenv("SNYK_TOKEN")
    if not snyk_token:
        snyk_token = input("Enter your Snyk API Token: ").strip()
        if not snyk_token:
            log.error("Snyk Token is required.")
            sys.exit(1)
    return snyk_token

def select_target_id(client, entity_type, env_var_name):
    """
    Handles selection of a target ID (org or group) from .env or user prompt.
    
    This function provides an interactive way to select which organization
    or group to analyze, with support for multiple IDs in the .env file.
    
    Args:
        client (SnykClient): The Snyk API client instance
        entity_type (str): Type of entity ('group' or 'org')
        env_var_name (str): Environment variable name to check for IDs
        
    Returns:
        str: The selected entity ID
        
    Exits:
        If no valid ID is provided by the user
    """
    ids_str = os.getenv(env_var_name)
    plural_entity = f"{entity_type}s"  # e.g., 'orgs' or 'groups'

    # If no IDs in environment, prompt user
    if not ids_str:
        entity_id = input(f"Enter the Snyk {entity_type.capitalize()} ID to analyze: ").strip()
        if not entity_id:
            log.error(f"{entity_type.capitalize()} ID is required.")
            sys.exit(1)
        return entity_id

    # Parse comma-separated IDs from environment
    ids = [entity_id.strip() for entity_id in ids_str.split(',')]
    
    # If only one ID, use it directly
    if len(ids) == 1:
        return ids[0]
    else:
        # Multiple IDs found - let user choose
        print(f"Multiple {entity_type.capitalize()} IDs found. Please choose one:")
        options = {}
        for i, entity_id in enumerate(ids):
            name = client.get_name(plural_entity, entity_id)
            options[i + 1] = (entity_id, name)
            print(f"  {i + 1}: {name} ({entity_id})")
        
        # Get user choice with validation
        while True:
            try:
                choice = int(input("Enter your choice (number): "))
                if choice in options:
                    return options[choice][0]
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except EOFError:
                print("Error: No input provided. Exiting.")
                sys.exit(1)

def sanitize_for_csv(value):
    """
    Sanitizes a value for CSV export to prevent formula injection.
    
    This function prevents CSV injection attacks by detecting and escaping
    potentially dangerous characters that could be interpreted as formulas
    by spreadsheet applications like Excel or Google Sheets.
    
    Args:
        value: The value to sanitize (can be any type)
        
    Returns:
        The sanitized value. If the value is a string starting with
        dangerous characters ('=', '+', '-', '@'), it prepends a single quote.
    """
    if isinstance(value, str) and value.startswith(('=', '+', '-', '@')):
        return f"'{value}"
    return value

def write_csv_report(report_data, filename, is_group_report=False, is_detailed=False):
    """
    Writes report data to a CSV file.
    
    This function handles both summary and detailed reports, with appropriate
    headers and data formatting for each type.
    
    Args:
        report_data (list): List of dictionaries containing report data
        filename (str): Output filename for the CSV report
        is_group_report (bool): Whether this is a group-level report (affects columns)
        is_detailed (bool): Whether this is a detailed report (affects structure)
    """
    if not report_data:
        log.warning("No data to write to report. Exiting.")
        return

    log.info("Step 3: Sorting report data...")
    
    if is_detailed:
        # Sort detailed reports by severity
        def sort_key_func(item):
            severity_order = SEVERITY_MAP.get(item.get('severity'), 99)
            if is_group_report:
                return (item.get('org_name', ''), item.get('project_name', ''), severity_order)
            else:
                return (item.get('project_name', ''), severity_order)
    else:
        # Sort summary reports by total issues
        sort_keys = ('total', 'critical', 'high', 'medium', 'low', 'org_name', 'name') if is_group_report else ('total', 'critical', 'high', 'medium', 'low', 'name')
        def sort_key_func(item):
            return tuple(item.get(k, '') for k in sort_keys)
    
    report_data.sort(key=sort_key_func)

    log.info(f"Step 4: Generating CSV report: {filename}")
    
    with open(filename, "w", newline="") as csvfile:
        # Use QUOTE_ALL to prevent CSV injection attacks
        writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        
        if is_detailed:
            # Detailed report headers
            header_map = {
                "org_name": "Organization", "project_name": "Project", "issue_id": "Issue ID",
                "title": "Title", "severity": "Severity", "type": "Type", "status": "Status",
                "package": "Package", "snyk_id": "Snyk ID", "url": "URL",
                "created_at": "Created At", "updated_at": "Updated At",
            }
            
            fieldnames = list(header_map.keys())
            if not is_group_report:
                fieldnames.remove('org_name')  # Remove org column for single-org reports

            headers_to_write = [header_map[k] for k in fieldnames]
            writer.writerow(headers_to_write)
            
            for row_dict in report_data:
                sanitized_row = [sanitize_for_csv(row_dict.get(k, "N/A")) for k in fieldnames]
                writer.writerow(sanitized_row)
        else:
            # Summary report headers
            if is_group_report:
                headers = ["Organization", "Project", "Critical", "High", "Medium", "Low", "Total"]
                writer.writerow(headers)
                for row in report_data:
                    writer.writerow([
                        sanitize_for_csv(row.get('org_name')),
                        sanitize_for_csv(row.get('name')),
                        row.get('critical'), row.get('high'),
                        row.get('medium'), row.get('low'),
                        row.get('total')
                    ])
            else:
                headers = ["Project", "Critical", "High", "Medium", "Low", "Total"]
                writer.writerow(headers)
                for row in report_data:
                    writer.writerow([
                        sanitize_for_csv(row.get('name')),
                        row.get('critical'), row.get('high'),
                        row.get('medium'), row.get('low'),
                        row.get('total')
                    ])

    log.info(f"✅ Report generation complete: {filename}")

# --- Main Logic ---
def extract_package_info(issue_type, resource):
    """
    Extracts package information from issue resource data.
    
    Args:
        issue_type (str): Type of issue (vuln, license, container, iac, code)
        resource (dict): Resource data from the issue
        
    Returns:
        str: Package information or file path
    """
    if issue_type in ['vuln', 'license', 'container']:
        # For package-based issues, extract package name and version
        if pkg := resource.get('pkg'):
            pkg_name = pkg.get('name', '')
            pkg_version = pkg.get('version', '')
            return f"{pkg_name}@{pkg_version}" if pkg_name and pkg_version else pkg_name
    elif issue_type in ['iac', 'code']:
        # For code/iac, the file path is a more useful identifier
        return resource.get('path', 'N/A')
    
    return "N/A"

def parse_detailed_issue(issue, project_map, org_name=None):
    """
    Parses a single raw issue from the API into a structured dictionary for detailed reporting.
    
    This function handles different structures for different issue types (vuln, code, iac, etc.)
    and extracts relevant information for the detailed report.
    
    Args:
        issue (dict): Raw issue data from the Snyk API
        project_map (dict): Mapping of project IDs to project names
        org_name (str, optional): Organization name for group reports
        
    Returns:
        dict: Structured issue data for CSV export, or None if issue should be excluded
    """
    attributes = issue.get("attributes", {})
    relationships = issue.get("relationships", {})
    scan_item = relationships.get("scan_item", {}).get("data", {})

    # Ensure the issue is linked to a project
    if not (scan_item and scan_item.get("type") == "project"):
        return None

    project_id = scan_item.get("id")
    # If a project map is provided, ensure the issue's project is in it (respects --limit)
    if project_map and project_id not in project_map:
        return None

    # Extract basic issue information
    issue_type = attributes.get("type")
    project_name = project_map.get(project_id, "Unknown Project")
    
    # Extract problem data (common for most types)
    problem = attributes.get("problem", {})
    problems = attributes.get("problems", [])
    
    # Try to get Snyk ID and URL from problems array
    snyk_id = "N/A"
    url = "N/A"
    
    if problems and len(problems) > 0:
        # Use the first problem for Snyk ID and URL
        first_problem = problems[0]
        snyk_id = first_problem.get("id", "N/A")
        url = first_problem.get("url", "N/A")
    elif problem:
        # Fallback to single problem object
        snyk_id = problem.get("id", "N/A")
        url = problem.get("url", "N/A")
    
    # For code issues, try to get URL from different locations
    if issue_type == "code" and url == "N/A":
        # Code issues might not have direct URLs, but we can construct them
        # or check if there's a URL in the attributes
        url = attributes.get("url", "N/A")

    # Extract package/resource information from coordinates
    package_info = "N/A"
    coordinates = attributes.get("coordinates", [])
    if coordinates:
        # The first coordinate usually has the most relevant info
        primary_coord = coordinates[0]
        representations = primary_coord.get("representations", [])

        # Find the most specific representation (dependency, sourceLocation, etc.)
        for rep in representations:
            if "dependency" in rep:
                dep = rep["dependency"]
                name = dep.get("package_name", "")
                version = dep.get("package_version", "")
                if name:
                    package_info = f"{name}@{version}" if version else name
                    break  # Found a good identifier
            elif "sourceLocation" in rep and issue_type == "code":
                file_path = rep["sourceLocation"].get("file", "N/A")
                if file_path != "N/A":
                    package_info = file_path
                    break # Found a file path for code issue

    # Fallback for older issue types or different structures
    if package_info == "N/A":
        package_info = extract_package_info(issue_type, attributes.get("resources", []))

    # Extract timestamps - try different possible field names
    created_at = attributes.get("createdAt") or attributes.get("created_at") or ""
    updated_at = attributes.get("updatedAt") or attributes.get("updated_at") or ""

    # Build the structured row data
    row = {
        "project_name": project_name, "issue_id": issue.get("id"),
        "title": attributes.get("title"), "severity": attributes.get("effective_severity_level"),
        "type": issue_type, "status": attributes.get("status"),
        "package": package_info, "snyk_id": snyk_id, "url": url,
        "created_at": created_at, "updated_at": updated_at,
    }
    if org_name:
        row["org_name"] = org_name
    return row

def process_summary_issues(all_issues):
    """
    Processes raw issue list into severity counts per project.
    
    This function aggregates issues by project and counts them by severity level.
    It's used for generating summary reports.
    
    Args:
        all_issues (list): Raw issue data from the Snyk API
        
    Returns:
        dict: Mapping of project_id to severity counts
    """
    issue_counts = {}
    for issue in all_issues:
        scan_item = issue.get("relationships", {}).get("scan_item", {}).get("data", {})
        if scan_item and scan_item.get("type") == "project":
            project_id = scan_item.get("id")
            severity = issue.get("attributes", {}).get("effective_severity_level")
            if project_id:
                if project_id not in issue_counts:
                    issue_counts[project_id] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                if severity in issue_counts[project_id]:
                    issue_counts[project_id][severity] += 1
    return issue_counts

def generate_report_data(projects, all_issues, detailed=False, org_name=None):
    """
    Generates report data from projects and issues.
    
    This function consolidates the logic for generating both summary and detailed reports.
    
    Args:
        projects (list): List of (project_id, project_name) tuples
        all_issues (list): Raw issue data from the Snyk API
        detailed (bool): Whether to generate detailed report data
        org_name (str, optional): Organization name for group reports
        
    Returns:
        list: Report data ready for CSV export
    """
    if detailed:
        # Generate detailed report with individual issues
        project_map = {pid: pname for pid, pname in projects}
        report_data = []
        for issue in all_issues:
            if parsed_issue := parse_detailed_issue(issue, project_map, org_name):
                report_data.append(parsed_issue)
        return report_data
    else:
        # Generate summary report with issue counts
        issue_counts = process_summary_issues(all_issues)
        report_data = []
        for project_id, project_name in projects:
            if not project_id or not project_name: 
                continue
            log.debug(f"Collating data for project: {project_name}")
            counts = issue_counts.get(project_id, {"critical": 0, "high": 0, "medium": 0, "low": 0})
            row = {
                "name": project_name,
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "total": sum(counts.values())
            }
            if org_name:
                row["org_name"] = org_name
            report_data.append(row)
        return report_data

def run_org_report(client, org_id, limit, detailed=False):
    """
    Generates a report for a single organization.
    
    This function orchestrates the entire reporting process for a single organization:
    1. Fetches all projects in the organization
    2. Retrieves all issues for the organization
    3. Processes the data (summary or detailed)
    4. Generates the appropriate CSV report
    
    Args:
        client (SnykClient): The Snyk API client instance
        org_id (str): The Snyk Organization ID
        limit (int, optional): Maximum number of projects to process
        detailed (bool): Whether to generate a detailed report (default: False)
    """
    log.info(f"Running report for Organization ID: {org_id}")
    org_name = client.get_name("orgs", org_id)
    log.info(f"Organization Name: {org_name}")

    log.info("Step 1: Fetching projects...")
    projects = client.get_projects_in_org(org_id, limit)
    if not projects:
        log.warning("No projects found or accessible in this organization.")
        return
    log.info(f"Found {len(projects)} projects to process.")

    log.info("Step 2: Fetching all issues for the organization...")
    all_issues = client.get_issues_in_org(org_id)

    # Generate report data
    report_data = generate_report_data(projects, all_issues, detailed)
    
    # Generate output filename and write report
    report_type = "detailed" if detailed else "summary"
    output_filename = f"snyk_org_report_{org_id}_{report_type}.csv"
    write_csv_report(report_data, output_filename, is_group_report=False, is_detailed=detailed)

def run_group_report(client, group_id, limit, detailed=False, max_workers=MAX_WORKERS, batch_size=BATCH_SIZE):
    """
    Generates a report for all organizations in a group using concurrent processing.
    
    This function orchestrates the reporting process for an entire group:
    1. Discovers all organizations in the group
    2. Processes organizations concurrently for better performance
    3. Processes the data (summary or detailed)
    4. Generates the appropriate CSV report
    
    Args:
        client (SnykClient): The Snyk API client instance
        group_id (str): The Snyk Group ID
        limit (int, optional): Maximum number of projects to process per organization
        detailed (bool): Whether to generate a detailed report (default: False)
        max_workers (int): Number of concurrent workers for processing
        batch_size (int): Number of organizations to process in a single batch
    """
    log.info(f"Running report for Group ID: {group_id}")
    group_name = client.get_name("groups", group_id)
    log.info(f"Group Name: {group_name}")

    log.info("Step 1: Discovering all organizations in the group...")
    organizations = client.get_orgs_in_group(group_id)
    if not organizations:
        log.warning("No organizations found or accessible in this group.")
        return
    log.info(f"Found {len(organizations)} organizations.")

    log.info("Step 2: Processing organizations concurrently...")
    start_time = time.time()
    
    # Process organizations in batches for better performance
    all_report_data = []
    
    # Process organizations in batches
    for i in range(0, len(organizations), batch_size):
        batch = organizations[i:i + batch_size]
        log.info(f"Processing batch {i//batch_size + 1}/{(len(organizations) + batch_size - 1)//batch_size} ({len(batch)} organizations)")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all organizations in this batch for concurrent processing
            future_to_org = {
                executor.submit(client.process_organization_concurrent, org_data, limit, detailed): org_data 
                for org_data in batch
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_org):
                org_data = future_to_org[future]
                org_id, org_name = org_data
                
                try:
                    org_report_data = future.result()
                    all_report_data.extend(org_report_data)
                    log.info(f"Completed: {org_name} ({len(org_report_data)} items)")
                except Exception as e:
                    log.error(f"Error processing {org_name}: {e}")

    elapsed_time = time.time() - start_time
    log.info(f"Concurrent processing completed in {elapsed_time:.1f} seconds")

    # Generate the final report
    report_type = "detailed" if detailed else "summary"
    output_filename = f"snyk_group_report_{group_id}_{report_type}.csv"
    write_csv_report(all_report_data, output_filename, is_group_report=True, is_detailed=detailed)

def main():
    """
    Main entry point for the Snyk Issue Reporter.
    
    This function handles command-line argument parsing, logging setup,
    and orchestrates the reporting process based on user input.
    """
    parser = argparse.ArgumentParser(
        description="Snyk Issue Reporter - Generate CSV reports of Snyk projects and issues.",
        epilog="""
Examples:
  python3 snyk_issue_reporter.py --org <org-id>
  python3 snyk_issue_reporter.py --group <group-id> --detailed
  python3 snyk_issue_reporter.py --org <org-id> --limit 10
""",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Define command-line arguments
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument("--org", metavar="ORG_ID", help="Run report for a single Snyk Organization ID.")
    scope_group.add_argument("--group", metavar="GROUP_ID", help="Run report for a single Snyk Group ID.")
    parser.add_argument("--limit", type=int, help="Limit the number of projects processed per organization.")
    parser.add_argument("--detailed", action="store_true", help="Generate a detailed, per-issue report instead of a summary.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging for verbose output.")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help=f"Number of concurrent workers (default: {MAX_WORKERS}).")
    parser.add_argument("--timeout", type=int, default=60, help="Request timeout in seconds (default: 60).")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE, help=f"Number of orgs to process in a batch (default: {BATCH_SIZE}).")

    args = parser.parse_args()

    # Configure logging based on debug flag
    log_level = logging.DEBUG if args.debug else logging.INFO
    # All logs go to stdout to be seen in order.
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s', stream=sys.stdout)

    if args.limit:
        log.info(f"Note: Project processing is limited to {args.limit} per organization.")
    
    if args.workers != MAX_WORKERS:
        log.info(f"Using {args.workers} concurrent workers.")

    log.info(f"Using request timeout of {args.timeout} seconds.")

    # Get Snyk token and initialize client
    snyk_token = get_snyk_token()
    client = SnykClient(snyk_token, timeout=args.timeout)

    # Execute the appropriate report based on arguments
    if args.org:
        run_org_report(client, args.org, args.limit, args.detailed)
    elif args.group:
        run_group_report(client, args.group, args.limit, args.detailed, max_workers=args.workers, batch_size=args.batch_size)
    else:
        # Interactive Mode - prompt user for scope and target
        log.info("No scope specified. Entering interactive mode.")
        while True:
            try:
                choice = input("Analyze a (g)roup or an (o)rganization? [g/o]: ").lower().strip()
                if choice in ['g', 'group']:
                    group_id = select_target_id(client, "group", "GROUP_IDS")
                    run_group_report(client, group_id, args.limit, args.detailed, max_workers=args.workers, batch_size=args.batch_size)
                    break
                elif choice in ['o', 'org', 'organization']:
                    org_id = select_target_id(client, "org", "ORG_IDS")
                    run_org_report(client, org_id, args.limit, args.detailed)
                    break
                else:
                    print("Invalid choice. Please enter 'g' or 'o'.")
            except EOFError:
                print("Error: No input provided. Exiting.")
                sys.exit(1)

if __name__ == "__main__":
    main()