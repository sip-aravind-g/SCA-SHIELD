# Hybrid Multiprocessing + Threading Image Scanner

This tool enables and simplifies hybrid multiprocessing and threading to scan images efficiently, triggering a JFrog Xray scan in one go for all components in a specified directory.

# Features
1. Scans images using multiprocessing for CPU bound tasks and threading for I/O operations.
2. Integrates with Jenkins to trigger JFrog Xray scans for multiple components simultaneously.
3. Handles large directories with parallel processing for faster execution.

# Prerequisites
1. Python 3.8+ with multiprocessing, threading, subprocess, and requests libraries.
2. Access to Jenkins instance with JFrog Xray job configured.
3. Valid credentials for Jenkins API.

# Configuration
Set these environment variables or replace placeholders in the script:

BASE_DIR = "<file-path>######-######-######/components/1.5.5/"
JENKINS_URL = "######-######-######"
USER = "######-######-######"
TOKEN = "######-######-######"
JOB_NAME = "xray_scan_images"

# Usage
Update the configuration with your values.
Run python run_xray.py.
The script discovers images in BASE_DIR, processes them in parallel, and triggers the Jenkins Xray job.
