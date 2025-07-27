#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import os
import sys
from urllib.parse import urljoin, urlparse, parse_qs
import time
import re
import datetime
import subprocess
import json
import shutil
import html
from tqdm import tqdm

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}
REQUEST_DELAY_SECONDS = 2
VERSIONS_TO_DOWNLOAD = 10

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RECapk Scan Secrets Report</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
    <style>
        body {{ padding: 20px; font-family: Arial, sans-serif; background-color: #f4f7f6; }}
        .container {{ width: 95%; max-width: 1400px; }}
        .header {{ text-align: center; margin-bottom: 30px; padding-bottom: 15px; border-bottom: 1px solid #ddd; }}
        .table-responsive {{ margin-top: 20px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
        .table > thead > tr > th {{ background-color: #343a40; color: #fff; border-bottom: 0; }}
        .table > tbody > tr:nth-of-type(odd) {{ background-color: #f9f9f9; }}
        .table > tbody > tr:hover {{ background-color: #f1f1f1; }}
        .secret-cell {{
            word-break: break-all;
            max-width: 550px;
            font-family: 'Courier New', Courier, monospace;
            background-color: #e9ecef;
            color: #c7254e;
        }}
        .locator-cell {{
            word-break: break-all;
            max-width: 400px;
        }}
        .parent-cell {{
            word-break: break-all;
            max-width: 250px;
            font-weight: bold;
        }}
        .index-cell {{ width: 50px; text-align: center; vertical-align: middle; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RECapk Scan Secrets Report</h1>
            <p class="lead"><strong>Scan Date:</strong> {scan_date}</p>
        </div>
        <div class="table-responsive">
            <table class="table table-bordered table-striped table-hover">
                <thead>
                    <tr>
                        <th class="index-cell">#</th>
                        <th class="parent-cell">Source File</th>
                        <th class="locator-cell">Locator (Path Inside APK)</th>
                        <th class="secret-cell">Secret Found</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""

def display_banner():
    banner = """
██████╗ ███████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗
██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔══██╗██║ ██╔╝
██████╔╝█████╗  ██║      ███████║██████╔╝█████╔╝ 
██╔══██╗██╔══╝  ██║      ██╔══██║██╔═══╝ ██╔═██╗ 
██║  ██║███████╗╚██████  ██║  ██║██║     ██║  ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
    """.lower()
    caption = "A Recon tool for Android APK's. Built by @praseudo"
    print(banner)
    print(caption)
    print("-" * len(caption))

def create_scan_directory():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    scan_dir = f"scan_{timestamp}"
    if not os.path.exists(scan_dir):
        os.makedirs(scan_dir)
    return scan_dir

def check_and_install_dependencies():
    try:
        subprocess.run(['apkscan', '--version'], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️ 'apkscan' not found.")
        install = input("Would you like to install it now via pip? (y/n): ").lower()
        if install == 'y':
            print("⏳ Installing 'apkscan'...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "apkscan", "--quiet", "--break-system-packages"])
                print("✅ 'apkscan' installed successfully.")
            except subprocess.CalledProcessError as e:
                print(f"❌ Error installing 'apkscan': {e}")
                return False
        else:
            print("❌ Cannot proceed without 'apkscan'. Exiting.")
            return False
    return True

def get_page_content(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        time.sleep(REQUEST_DELAY_SECONDS)
        return BeautifulSoup(response.text, 'html.parser')
    except requests.exceptions.RequestException:
        return None

def download_file(url, filename, download_dir):
    file_path = os.path.join(download_dir, filename)
    if os.path.exists(file_path):
        return file_path
    try:
        response = requests.get(url, stream=True, headers=HEADERS, timeout=60)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        with open(file_path, 'wb') as f, tqdm(
            desc=filename,
            total=total_size,
            unit='iB',
            unit_scale=True,
            unit_divisor=1024,
            leave=False,
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}'
        ) as bar:
            for chunk in response.iter_content(chunk_size=1024):
                size = f.write(chunk)
                bar.update(size)
        return file_path
    except requests.exceptions.RequestException:
        return None

def extract_app_info_from_url(url):
    parsed_url = urlparse(url)
    path_segments = [s for s in parsed_url.path.split('/') if s]
    if len(path_segments) >= 2:
        return path_segments[0], path_segments[1]
    return None, None

def find_direct_apk_download_link(version_download_page_url):
    soup = get_page_content(version_download_page_url)
    if not soup: return None
    for link in soup.find_all('a', href=True):
        href = link['href']
        if 'd.apkpure.net' in href and ('/b/' in href or '.apk' in href or '.xapk' in href):
            return href
    return None

def process_apkpure_versions_page(versions_url, scan_dir):
    soup = get_page_content(versions_url)
    if not soup: return []
    app_name_slug, package_name = extract_app_info_from_url(versions_url)
    if not app_name_slug or not package_name:
        return []

    version_link_pattern = re.compile(rf'^{re.escape(f"/{app_name_slug}/{package_name}/download/")}([\w\d\.-]+)$')
    version_download_links = [urljoin(versions_url, a['href']) for a in soup.find_all('a', href=version_link_pattern)]
    
    unique_links = sorted(list(set(version_download_links)), reverse=True)
    links_to_process = unique_links[:VERSIONS_TO_DOWNLOAD]

    if not links_to_process:
        return []

    downloaded_files = []
    for version_page_url in links_to_process:
        version_string = urlparse(version_page_url).path.split('/')[-1] or "unknown"
        direct_apk_url = find_direct_apk_download_link(version_page_url)
        if direct_apk_url:
            query_params = parse_qs(urlparse(direct_apk_url).query)
            version_code = query_params.get('versionCode', [version_string])[0]
            file_extension = ".xapk" if "/b/XAPK/" in direct_apk_url else ".apk"
            final_filename = re.sub(r'[\\/:*?"<>|]', '_', f"{package_name}-{version_code}{file_extension}")
            downloaded_path = download_file(direct_apk_url, final_filename, scan_dir)
            if downloaded_path:
                downloaded_files.append(downloaded_path)
    return [os.path.basename(f) for f in downloaded_files]

def run_apkscan(scan_dir, target_files):
    if not target_files:
        return
    
    command = ['apkscan'] + target_files
    try:
        process = subprocess.Popen(command, cwd=scan_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        with tqdm(total=len(target_files), desc="🛡️  Scanning APKs", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
            for line in process.stdout:
                if "Processing" in line:
                    pbar.update(1)
    except Exception:
        pass

def find_and_move_file(search_dir, filename, dest_dir):
    for root, _, files in os.walk(search_dir):
        if filename in files:
            source_path = os.path.join(root, filename)
            dest_path = os.path.join(dest_dir, filename)
            shutil.move(source_path, dest_path)
            return dest_path
    return None

def extract_secrets_recursively(data, parent_key="N/A"):
    findings = []
    if isinstance(data, dict):
        if "locator" in data and "secret" in data:
            findings.append({
                "parent": parent_key,
                "locator": data.get("locator"),
                "secret": data.get("secret")
            })
        for key, value in data.items():
            findings.extend(extract_secrets_recursively(value, parent_key=key))
    elif isinstance(data, list):
        for item in data:
            findings.extend(extract_secrets_recursively(item, parent_key=parent_key))
    return findings

def generate_html_report(scan_dir, json_path, report_filename):
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        all_findings = extract_secrets_recursively(data)
        
        table_rows = []
        if all_findings:
            for i, item in enumerate(all_findings, 1):
                parent = html.escape(str(item.get("parent", "N/A")))
                locator = html.escape(str(item.get("locator", "N/A")))
                secret = html.escape(str(item.get("secret", "N/A")))
                row = (
                    f'<tr>'
                    f'<td class="index-cell">{i}</td>'
                    f'<td class="parent-cell">{parent}</td>'
                    f'<td class="locator-cell">{locator}</td>'
                    f'<td class="secret-cell">{secret}</td>'
                    f'</tr>'
                )
                table_rows.append(row)
        else:
            table_rows.append('<tr><td colspan="4" class="text-center">No secrets found.</td></tr>')

        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        final_html = HTML_TEMPLATE.format(
            scan_date=scan_date,
            table_rows="\n".join(table_rows)
        )

        report_path = os.path.join(scan_dir, report_filename)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(final_html)
        print(f"✅ HTML report created: {report_path}")

    except Exception:
        print(f"❌ An error occurred during report generation.")

def cleanup_scan_directory(scan_dir, files_to_keep):
    try:
        for item_name in os.listdir(scan_dir):
            if item_name not in files_to_keep:
                item_path = os.path.join(scan_dir, item_name)
                try:
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                except Exception:
                    pass
    except Exception:
        pass

def main():
    display_banner()
    if not check_and_install_dependencies():
        return

    try:
        input_file = input("Enter the path to the text file containing Apkpure URLs: ")
        if not os.path.exists(input_file):
            print(f"❌ Error: File not found at '{input_file}'")
            return
        with open(input_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and urlparse(line.strip()).scheme]
        if not urls:
            print("❌ No valid URLs found in the input file.")
            return
    except Exception as e:
        print(f"❌ An error occurred reading the input file: {e}")
        return

    scan_dir = create_scan_directory()
    all_downloaded_files = []

    print(f"\n🔎 Found {len(urls)} URLs to process.")
    with tqdm(total=len(urls), desc="Overall Progress", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
        for url in urls:
            pbar.set_description(f"Processing {urlparse(url).path.split('/')[1]}")
            downloaded_for_url = process_apkpure_versions_page(url, scan_dir)
            all_downloaded_files.extend(downloaded_for_url)
            pbar.update(1)

    run_apkscan(scan_dir, all_downloaded_files)

    secrets_json_path = find_and_move_file(scan_dir, "secrets_output.json", scan_dir)
    
    if secrets_json_path:
        print("📄 Generating HTML report...")
        generate_html_report(scan_dir, secrets_json_path, "secrets.html")
        print("🧹 Cleaning up workspace...")
        cleanup_scan_directory(scan_dir, ["secrets.html", "secrets_output.json"])
    else:
        print("\n🟡 'secrets_output.json' not found. Skipping report generation.")
        print("🧹 Cleaning up workspace...")
        cleanup_scan_directory(scan_dir, [])

    print("\n--- ✅ All operations complete ---")

if __name__ == "__main__":
    main()
