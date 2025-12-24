import json
import os
from elasticsearch import Elasticsearch, helpers

# --- CONFIGURATION ---
# Authentication - Populate these or use Environment Variables
CLOUD_ID = os.getenv("ELASTIC_CLOUD_ID", "your_cloud_id_here")
API_KEY = os.getenv("ELASTIC_API_KEY", None) # Preferred for Cloud

# Fallback/Self-hosted Authentication
ES_HOST = os.getenv("ELASTIC_HOST", "https://localhost:9200")
ES_USER = os.getenv("ELASTIC_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD", "password")

# Data Configuration
INDEX_NAME = "your-custom-index"
DATA_FILE_PATH = "your_data.json" # Path to your JSON file, can do CSV as well

def get_client():
    """Initializes the Elasticsearch client based on available credentials."""
    try:
        # 1. Try Cloud ID + API Key (Modern Cloud Auth)
        if CLOUD_ID and API_KEY:
            print("Connecting to Elastic Cloud via API Key...")
            return Elasticsearch(
                cloud_id=CLOUD_ID,
                api_key=API_KEY
            )
        
        # 2. Try Cloud ID + Basic Auth
        elif CLOUD_ID and ES_USER and ES_PASS:
            print("Connecting to Elastic Cloud via Username/Password...")
            return Elasticsearch(
                cloud_id=CLOUD_ID,
                basic_auth=(ES_USER, ES_PASS)
            )

        # 3. Fallback to Host (Self-hosted/On-prem)
        else:
            print(f"Connecting to host {ES_HOST}...")
            return Elasticsearch(
                ES_HOST,
                basic_auth=(ES_USER, ES_PASS),
                verify_certs=True # Set to False if using self-signed certs without CA
            )
    except Exception as e:
        print(f"Failed to initialize client: {e}")
        return None

def load_data(file_path):
    """Loads a list from a JSON file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        # Ensure data is a list
        return data if isinstance(data, list) else [data]

def generate_actions(data):
    """Generator for bulk indexing."""
    for entry in data:
        yield {
            "_index": INDEX_NAME,
            "_source": entry
        }

def main():
    # Initialize Client
    es = get_client()
    if not es or not es.ping():
        print("Could not connect to Elasticsearch. Check your credentials.")
        return

    # Load Source Data
    if not os.path.exists(DATA_FILE_PATH):
        print(f"Error: File {DATA_FILE_PATH} not found.")
        return
    
    data = load_data(DATA_FILE_PATH)
    print(f"Loaded {len(data)} documents from {DATA_FILE_PATH}")

    # Index Data
    print(f"Starting bulk indexing to index: {INDEX_NAME}...")
    try:
        success, failed = helpers.bulk(es, generate_actions(data))
        print(f"Successfully indexed: {success}")
        if failed:
            print(f"Failed to index: {failed}")
    except Exception as e:
        print(f"An error occurred during indexing: {e}")

if __name__ == "__main__":
    main()
