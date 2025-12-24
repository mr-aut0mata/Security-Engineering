# Elastic Data Ingest Template

A generic Python utility for bulk-loading JSON data into Elasticsearch. This script supports modern authentication for both Elastic Cloud (API Keys) and self-hosted environments.

### Features
*   **Flexible Auth:** Automatically detects whether to use Cloud ID/API Key or standard host/user/pass.
*   **Bulk API:** Uses the Elasticsearch Bulk helper for high-performance indexing.
*   **Generic Loader:** Works with any JSON file containing a list of objects.

### Prerequisites
*   Python 3.x
*   Elasticsearch Python client: `pip install elasticsearch`

### Configuration
The script looks for the following environment variables. You can set these in your terminal or via a `.env` file.

| Variable | Description |
| :--- | :--- |
| `ELASTIC_CLOUD_ID` | Your Elastic Cloud ID. |
| `ELASTIC_API_KEY` | Your Base64 encoded API Key. |
| `ELASTIC_HOST` | The URL of your instance (e.g., `https://localhost:9200`). |
| `ELASTIC_USER` | Username (default: `elastic`). |
| `ELASTIC_PASSWORD` | Password for the user. |
| `INDEX_NAME` | The target index for your data. |
| `DATA_FILE_PATH` | Path to your `.json` data source. |

### Usage
1. Set your credentials as environment variables (e.g., `export ELASTIC_API_KEY="your_key"`).
2. Ensure your data file is formatted as a JSON list.
3. Run the script:
   ```bash
   python elastic_ingest.py
