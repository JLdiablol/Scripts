# python3 --version
# python3 -m ensurepip --upgrade
# pip3 --version
# pip3 install playwright requests
# playwright install

from playwright.sync_api import sync_playwright
import requests

def expand_url(short_url):
    try:
        return requests.head(short_url, allow_redirects=True).url
    except Exception as e:
        print(f"[ERROR]: Failed to expand {short_url}: {e}")
        return None

def download_from_internet(short_urls, save_folder="downloads"):
    import os
    os.makedirs(save_folder, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()

        for i, short_url in enumerate(short_urls):
            real_url = expand_url(short_url)
            if not real_url:
                continue

            print(f"\n🔗 [{i+1}] Real URL: {real_url}")
            page = context.new_page()
            video_url = None

            def handle_route(route, request):
                nonlocal video_url
                if "video" in request.url and (".mp4" in request.url or ".m3u8" in request.url):
                    video_url = request.url
                    print(f"🎯 Found video: {video_url}")
                route.continue_()

            context.route("**/*", handle_route)
            page.goto(real_url)
            page.wait_for_timeout(10000)  

            if video_url:
                ext = ".mp4" if ".mp4" in video_url else ".ts"
                filename = os.path.join(save_folder, f"download_video_{i+1}{ext}")
                print(f"[DOWNLOADING]: Downloading to {filename} ...")
                try:
                    video_data = requests.get(video_url).content
                    with open(filename, "wb") as f:
                        f.write(video_data)
                    print(f"[SUCCESS]: Saved: {filename}")
                except Exception as e:
                    print(f"[ERROR]: Download failed: {e}")
            else:
                print("[ERROR]: No video found in network requests.")

            page.close()

        browser.close()


short_links = [
    "",
    ""
]

download_from_internet(short_links)

