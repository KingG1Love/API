import requests
from bs4 import BeautifulSoup
import re
import json
from datetime import datetime

def parse_apple_security():
    url = "https://support.apple.com/en-us/HT201222"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return

    soup = BeautifulSoup(response.text, "html.parser")
    
    # Регулярка для ссылок на статьи саппорта: /en-us/HT123456 или /en-us/123456
    links = soup.find_all('a', href=re.compile(r'/en-us/(HT\d+|\d{6})'))
    
    cve_results = []
    cve_set = set()
    
    processed_articles = 0
    # Открываем 5 последних обновлений
    for link in links:
        if processed_articles >= 5:
            break
            
        article_url = link.get('href')
        if not article_url.startswith('http'):
            article_url = "https://support.apple.com" + article_url
            
        print(f"Scraping: {article_url} ...")
        try:
            art_resp = requests.get(article_url, headers=headers)
            art_soup = BeautifulSoup(art_resp.text, "html.parser")
            page_text = art_soup.get_text()
            
            # Ищем Идентификаторы CVE
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', page_text)
            
            release_date_iso = datetime.utcnow().isoformat() + "Z"
            
            added_any = False
            for cve in cves:
                if cve not in cve_set:
                    cve_set.add(cve)
                    cve_results.append({
                        "ID": cve,
                        "vendor_release_date": release_date_iso,
                        "vendor_release_url": article_url
                    })
                    added_any = True
            
            if added_any:
                print(f"  Found {len(set(cves))} new CVEs in this article.")
                processed_articles += 1
                
        except Exception as e:
            print(f"Error scraping {article_url}: {e}")

    with open('result_task_1.json', 'w', encoding='utf-8') as f:
        json.dump(cve_results, f, indent=4)
        
    print(f"Total CVEs collected: {len(cve_results)}")
    print("Saved to result_task_1.json")

if __name__ == "__main__":
    print("Starting Task 1...")
    parse_apple_security()
