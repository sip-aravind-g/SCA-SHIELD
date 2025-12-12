#!/usr/bin/env python3
"""
Hybrid Multiprocessing + Threading Image Scanner
Author: Aravind G | Hybrid Cloud DevSecOps Senior Cloud Engineer
Email: ezsecops@xxx.com

Purpose:
    - Scan path: EUA/components/1.5.4/
    - Scan path: AIE/components/1.5.4/
    - Scan path: ERE/components/1.5.4/
    - Each folder contains IMAGES file
    - Each IMAGES file contains docker image names
    - For each image_name → trigger Jenkins job: xray_scan_job
    - Jenkins expects input parameter: image_name=<value>
"""

import os
import glob
import time
import queue
import logging
import requests
import threading
import multiprocessing
from multiprocessing import Process


#LOGGING============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(processName)s - %(message)s",
)

# JENKINS_CLIENT============================================================================
class JenkinsClient:
    """Simple Jenkins API wrapper."""

    def __init__(self, base_url, user, token, job_name):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.token = token
        self.job_name = job_name

    def trigger_job(self, image_name):
        """Trigger Jenkins with image_name parameter."""
        try:
            job_url = f"{self.base_url}/job/{self.job_name}/buildWithParameters"
            payload = {"image_name": image_name, "CSV_REPORT": True}  # <<< Correct key

            response = requests.post(
                job_url,
                auth=(self.user, self.token),
                params=payload,
                timeout=20,
                verify=False
            )

            if response.status_code in [200, 201, 202]:
                logging.info(f"Triggered Jenkins job for: {image_name}")
            else:
                logging.error(
                    f"Failed triggering job for {image_name}, HTTP={response.status_code}"
                )

        except Exception as e:
            logging.error(f"Exception triggering job for {image_name}: {e}")


#THREAD_WORKER============================================================================

def thread_worker(q_images, jenkins_client):
    """Thread worker to process each image_name."""
    while True:
        try:
            image = q_images.get_nowait()
        except queue.Empty:
            break

        jenkins_client.trigger_job(image)
        time.sleep(0.2)   # Soft throttle to avoid flooding Jenkins


#PROCESS_WORKER============================================================================
def process_component(folder_path, jenkins_cfg):
    """Each process handles one component folder."""
    logging.info(f"Processing folder: {folder_path}")

    images_file = os.path.join(folder_path, "IMAGES")

    if not os.path.isfile(images_file):
        logging.warning(f"IMAGES file missing in: {folder_path}")
        return

    # Read docker images
    with open(images_file, "r") as f:
        images = [line.strip() for line in f.readlines() if line.strip()]

    if not images:
        logging.warning(f"No images found inside: {images_file}")
        return

    q_images = queue.Queue()
    for img in images:
        q_images.put(img)

    jc = JenkinsClient(
        base_url=jenkins_cfg["url"],
        user=jenkins_cfg["user"],
        token=jenkins_cfg["token"],
        job_name=jenkins_cfg["job_name"]
    )

    threads = []
    num_threads = min(10, len(images))

    for _ in range(num_threads):
        t = threading.Thread(target=thread_worker, args=(q_images, jc))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    logging.info(f"Completed folder: {folder_path}")


#EXECUTOR_CLASS============================================================================
class ImageScanExecutor:

    def __init__(self, base_path, jenkins_url, user, token, job_name):
        self.base_path = os.path.abspath(base_path)
        self.jenkins_cfg = {
            "url": jenkins_url,
            "user": user,
            "token": token,
            "job_name": job_name
        }

    def get_component_dirs(self):
        """Discover all folders inside base_path."""
        pattern = os.path.join(self.base_path, "*")
        return [d for d in glob.glob(pattern) if os.path.isdir(d)]

    def run(self):
        logging.info(f"Scanning base path: {self.base_path}")

        component_dirs = self.get_component_dirs()

        if not component_dirs:
            logging.error("No component directories found!")
            return

        logging.info(f"Found {len(component_dirs)} folders.")

        processes = []
        for folder in component_dirs:
            p = Process(target=process_component, args=(folder, self.jenkins_cfg))
            p.start()
            processes.append(p)

        for p in processes:
            p.join()

        logging.info("All processing complete.")


#MAIN============================================================================

if __name__ == "__main__":

    BASE_DIR = "/components/1.5.4/"
    JENKINS_URL = "https://X0.X27.X08.X84:8443"
    USER = "XXXXXX"
    TOKEN = "11d541b5af6d56935638f733XXXXXX"
    JOB_NAME = "xray_scan_images"

    executor = ImageScanExecutor(
        base_path=BASE_DIR,
        jenkins_url=JENKINS_URL,
        user=USER,
        token=TOKEN,
        job_name=JOB_NAME
    )

    executor.run()
