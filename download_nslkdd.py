import os
import requests
from tqdm import tqdm

# NSL-KDD dataset URLs from UNB CIC
BASE_URL = "https://github.com/defcom17/NSL_KDD/raw/master"
FILES = {
    "KDDTrain+.txt": f"{BASE_URL}/KDDTrain+.txt",
    "KDDTest+.txt": f"{BASE_URL}/KDDTest+.txt"
}

# Create data directory if it doesn't exist
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

def download_file(url, filename):
    """Download a file with progress bar."""
    filepath = os.path.join(DATA_DIR, filename)
    
    # Check if file already exists
    if os.path.exists(filepath):
        print(f"{filename} already exists in {DATA_DIR}/")
        return
    
    print(f"Downloading {filename}...")
    
    # Stream download with progress bar
    response = requests.get(url, stream=True)
    response.raise_for_status()
    
    total_size = int(response.headers.get('content-length', 0))
    
    with open(filepath, 'wb') as f, tqdm(
        desc=filename,
        total=total_size,
        unit='B',
        unit_scale=True,
        unit_divisor=1024,
    ) as progress_bar:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                progress_bar.update(len(chunk))
    
    print(f"Successfully downloaded {filename} to {DATA_DIR}/")

def main():
    """Download all NSL-KDD dataset files."""
    print("Starting NSL-KDD dataset download...")
    print(f"Files will be saved to: {DATA_DIR}/\n")
    
    for filename, url in FILES.items():
        try:
            download_file(url, filename)
        except Exception as e:
            print(f"Error downloading {filename}: {e}")
    
    print("\nDownload complete!")

if __name__ == "__main__":
    main()
