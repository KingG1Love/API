import requests
from bs4 import BeautifulSoup
import re
import json
from datetime import datetime, timezone

BASE_URL = "https://support.apple.com"
INDEX_URL = f"{BASE_URL}/en-us/HT201222"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# Форматы дат, встречающиеся на страницах Apple
DATE_FORMATS = [
    "%B %d, %Y",   # April 27, 2026
    "%b %d, %Y",   # Apr 27, 2026
    "%Y-%m-%d",    # 2026-04-27
]


def parse_release_date(date_str: str) -> str:
    """Парсит строку даты с Apple-страницы и возвращает ISO 8601 (UTC)."""
    date_str = date_str.strip()
    for fmt in DATE_FORMATS:
        try:
            dt = datetime.strptime(date_str, fmt)
            # Формируем ISO 8601 без микросекунд
            return dt.strftime('%Y-%m-%dT00:00:00Z')
        except ValueError:
            continue
    # Если формат не распознан — текущее время без микросекунд
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def scrape_article_cves(article_url: str, session: requests.Session) -> list:
    """Скрапит статью Apple и возвращает упорядоченный список CVE-идентификаторов."""
    resp = session.get(article_url, timeout=15)
    resp.raise_for_status()
    text = BeautifulSoup(resp.text, "html.parser").get_text()
    # dict.fromkeys сохраняет порядок и убирает дубликаты
    return list(dict.fromkeys(re.findall(r'CVE-\d{4}-\d{4,7}', text)))


def parse_apple_security():
    with requests.Session() as session:
        session.headers.update(HEADERS)

        try:
            resp = session.get(INDEX_URL, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"Ошибка при загрузке индексной страницы: {e}")
            return

        soup = BeautifulSoup(resp.text, "html.parser")

        # На странице HT201222 — таблица вида: [Name (link) | Available for | Release Date]
        table = soup.find('table')
        if not table:
            print("Таблица с релизами не найдена.")
            return

        cve_results = []
        cve_seen = set()
        processed = 0

        for row in table.find_all('tr'):
            if processed >= 5:
                break

            cells = row.find_all('td')
            if not cells:
                continue  # пропускаем заголовок

            # Ссылка на статью — в первой ячейке
            link_tag = cells[0].find('a', href=re.compile(r'/en-us/(HT\d+|\d{6,})'))
            if not link_tag:
                continue

            article_url = link_tag['href']
            if not article_url.startswith('http'):
                article_url = BASE_URL + article_url

            # Дата релиза — в последней ячейке
            date_str = cells[-1].get_text(strip=True)
            release_date = parse_release_date(date_str)

            print(f"Scraping: {article_url}  (дата релиза: {date_str})")

            try:
                cves = scrape_article_cves(article_url, session)
            except requests.RequestException as e:
                print(f"  Ошибка: {e}")
                continue

            new_cves = [c for c in cves if c not in cve_seen]
            if not new_cves:
                continue

            for cve in new_cves:
                cve_seen.add(cve)
                cve_results.append({
                    "ID": cve,
                    "vendor_release_date": release_date,
                    "vendor_release_url": article_url,
                })

            print(f"  Найдено {len(new_cves)} новых CVE")
            processed += 1

    with open('result_task_1.json', 'w', encoding='utf-8') as f:
        json.dump(cve_results, f, indent=4, ensure_ascii=False)

    print(f"Всего CVE собрано: {len(cve_results)}")
    print("Сохранено в result_task_1.json")


if __name__ == "__main__":
    print("Starting Task 1...")
    parse_apple_security()
