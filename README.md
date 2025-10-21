# VirusTotal Bulk APK Scanner

A Python script to bulk-scan APK files using the VirusTotal v3 API and generate multi-format analysis reports (JSON, TXT, XML).

## Features

* **Bulk Scanning:** Automatically scans all `.apk` files placed in the `apks/` directory.
* **Multi-Format Reports:** Generates `.json`, `.txt`, and `.xml` reports for each scanned file.
* **API Rate Limit Friendly:** Includes a built-in delay to comply with the free VirusTotal API limits (4 requests/minute).
* **Size Check:** Skips files larger than the 32MB public API limit.
* **Summary Report:** Creates a final `results.txt` file summarizing the detection ratios for all files.

## How to Use

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Set API Key:**
    * Create a `.env` file in the root directory.
    * Add your VirusTotal API key to it:
        ```env
        VT_API_KEY="YOUR_API_KEY_HERE"
        ```

3.  **Add Files:**
    * Create a folder named `apks`.
    * Place all the `.apk` files you want to scan inside this `apks` folder.

4.  **Run the Script:**
    ```bash
    python scan_apks.py
    ```

## Output

* **Detailed Reports:** All individual analysis reports will be saved inside the `reports/` directory.
* **Summary:** A summary of all scans will be saved in `results.txt` in the root folder.

---