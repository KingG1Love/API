import json
import re
import time
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── API endpoints ──────────────────────────────────────────────────────────────
MITRE_CVE_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
CWE_API_URL = "https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_num}"

MAX_WORKERS = 8
NVD_RETRY_WAIT = 7

# ── Thread-local session ───────────────────────────────────────────────────────
_local = threading.local()


def get_session() -> requests.Session:
    if not hasattr(_local, 'session'):
        s = requests.Session()
        s.headers.update({"User-Agent": "CVE-Enricher/2.0"})
        _local.session = s
    return _local.session


# ══════════════════════════════════════════════════════════════════════════════
# ФАЗА 1: Обогащение CVE (параллельно)
# ══════════════════════════════════════════════════════════════════════════════

def fetch_from_nvd(cve_id: str) -> tuple[list, list]:
    for attempt in range(3):
        try:
            resp = get_session().get(NVD_CVE_URL.format(cve_id=cve_id), timeout=20)
            if resp.status_code == 200:
                break
            if resp.status_code == 429:
                print(f"  [NVD] Rate-limit для {cve_id}, ожидание {NVD_RETRY_WAIT}с...")
                time.sleep(NVD_RETRY_WAIT)
                continue
            return [], []
        except Exception as e:
            print(f"  [NVD] Ошибка для {cve_id}: {e}")
            return [], []
    else:
        return [], []

    vulns = resp.json().get('vulnerabilities', [])
    if not vulns:
        return [], []

    cve_data = vulns[0].get('cve', {})

    # CPE с диапазонами версий
    cpe_entries = []
    for config in cve_data.get('configurations', []):
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if not match.get('vulnerable', False):
                    continue
                cpe = match.get('criteria', '')
                if not cpe:
                    continue
                parts = []
                if match.get('versionStartIncluding'):
                    parts.append(f">={match['versionStartIncluding']}")
                elif match.get('versionStartExcluding'):
                    parts.append(f">{match['versionStartExcluding']}")
                if match.get('versionEndExcluding'):
                    parts.append(f"<{match['versionEndExcluding']}")
                elif match.get('versionEndIncluding'):
                    parts.append(f"<={match['versionEndIncluding']}")
                cpe_entries.append(f"{cpe} ({', '.join(parts)})" if parts else cpe)

    # CWE IDs
    cwe_ids = []
    for w in cve_data.get('weaknesses', []):
        for desc in w.get('description', []):
            val = desc.get('value', '')
            if re.match(r'^CWE-\d+$', val) and val not in cwe_ids:
                cwe_ids.append(val)

    return list(dict.fromkeys(cpe_entries)), cwe_ids


def enrich_single(item: dict, index: int, total: int) -> dict | None:
    """
    Фаза 1: обогащаем одну CVE.
    CWE IDs собираем как простой список строк
    """
    cve_id = item['ID']
    print(f"[{index}/{total}] Обрабатываем {cve_id}...")

    # MITRE CVE API
    try:
        resp = get_session().get(MITRE_CVE_URL.format(cve_id=cve_id), timeout=15)
        if resp.status_code != 200:
            print(f"  [!] MITRE вернул {resp.status_code} для {cve_id}")
            return None
        data = resp.json()
    except Exception as e:
        print(f"  [X] MITRE ошибка для {cve_id}: {e}")
        return None

    meta = data.get('cveMetadata', {})
    containers = data.get('containers', {})
    cna = containers.get('cna', {})

    descs = cna.get('descriptions', [])
    desc_text = next(
        (d.get('value', '') for d in descs if d.get('lang', '').startswith('en')),
        descs[0].get('value', '') if descs else ''
    )

    # CVSS из блоков ADP
    cvss_list = []
    for adp in containers.get('adp', []):
        for metric in adp.get('metrics', []):
            for key in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0', 'cvssV2'):
                if key not in metric:
                    continue
                cd = metric[key]
                cvss_list.append({
                    "version": key.lower().replace('_', ''),
                    "score": cd.get('baseScore', 0),
                    "vector": cd.get('vectorString', ''),
                    "severity": cd.get('baseSeverity', cd.get('severity', 'UNKNOWN'))
                })

    # CWE IDs из MITRE CNA (Apple обычно не заполняет)
    cwe_ids_mitre = []
    for pt in cna.get('problemTypes', []):
        for desc in pt.get('descriptions', []):
            cwe_id = desc.get('cweId', '')
            if not cwe_id:
                m = re.search(r'CWE-\d+', desc.get('description', ''))
                if m:
                    cwe_id = m.group(0)
            if cwe_id and cwe_id not in cwe_ids_mitre:
                cwe_ids_mitre.append(cwe_id)

    # NVD: CPE + CWE IDs
    cpe_list, cwe_ids_nvd = fetch_from_nvd(cve_id)

    # Объединяем CWE IDs без дубликатов
    all_cwe_ids = list(dict.fromkeys(cwe_ids_mitre + cwe_ids_nvd))

    if all_cwe_ids:
        print(f"  [CWE] Найдено IDs: {all_cwe_ids}")
    else:
        print(f"  [CWE] Нет CWE для {cve_id}")

    return {
        "ID": cve_id,
        "vendor_release_date": item.get('vendor_release_date'),
        "vendor_release_url": item.get('vendor_release_url'),
        "url": f"https://www.cve.org/CVERecord?id={cve_id}",
        "published_date": meta.get('datePublished', ''),
        "updated_date": meta.get('dateUpdated', ''),
        "description": desc_text,
        "cvss_list": cvss_list,
        "cpe_list": cpe_list,
        "cwe_ids": all_cwe_ids,  # просто список ID, без name/description
    }


# ══════════════════════════════════════════════════════════════════════════════
# Загрузка деталей CWE из MITRE CWE API
# ══════════════════════════════════════════════════════════════════════════════

def fetch_cwe_info(cwe_id: str, session: requests.Session) -> dict:

    num = re.sub(r'\D', '', cwe_id)
    url = CWE_API_URL.format(cwe_num=num)

    for attempt in range(4):
        try:
            resp = session.get(url, timeout=15)

            if resp.status_code == 404:
                print(f"  [CWE-API] {cwe_id}: 404 Not Found")
                return {"name": "", "description": ""}

            if resp.status_code == 429:
                wait = 10 * (attempt + 1)
                print(f"  [CWE-API] {cwe_id}: rate-limit, ожидание {wait}с...")
                time.sleep(wait)
                continue

            if resp.status_code != 200:
                print(f"  [CWE-API] {cwe_id}: HTTP {resp.status_code}, попытка {attempt + 1}/4")
                time.sleep(2 ** attempt)
                continue


            try:
                data = resp.json()
            except Exception as e:
                print(f"  [CWE-API] {cwe_id}: не удалось разобрать JSON: {e}")
                return {"name": "", "description": ""}

            # Извлекаем блок Weakness
            weaknesses_block = data.get('Weaknesses') or data.get('weaknesses') or {}

            if isinstance(weaknesses_block, list):
                items = weaknesses_block
            elif isinstance(weaknesses_block, dict):
                items = weaknesses_block.get('Weakness') or weaknesses_block.get('weakness') or []
                if isinstance(items, dict):
                    items = [items]
            else:
                items = []

            if not items:
                print(f"  [CWE-API] {cwe_id}: список CWE пуст в ответе")
                return {"name": "", "description": ""}

            w = items[0]

            # XML атрибуты в JSON получают префикс '@'
            name = w.get('@Name') or w.get('Name') or w.get('@name') or w.get('name') or ''

            # Функция для рекурсивного извлечения текста
            def extract_text(node):
                if isinstance(node, dict):
                    # Если текст лежит как значение ключа #text
                    return node.get('#text') or node.get('text') or node.get('_text') or ''
                elif isinstance(node, list):
                    return " ".join([extract_text(n) for n in node])
                else:
                    return str(node)

            raw_desc = w.get('Description') or w.get('description') or ''
            desc = extract_text(raw_desc).strip()

            # Если Description оказалось пустым, пробуем Extended_Description
            if not desc:
                raw_ext = w.get('Extended_Description') or w.get('extended_description') or ''
                desc = extract_text(raw_ext).strip()

            print(f"  [CWE-API] OK {cwe_id} -> {name}")
            return {"name": name, "description": desc}

        except requests.exceptions.Timeout:
            print(f"  [CWE-API] {cwe_id}: таймаут, попытка {attempt + 1}/4")
            time.sleep(2 ** attempt)
        except Exception as e:
            print(f"  [CWE-API] {cwe_id}: неожиданная ошибка: {type(e).__name__}: {e}")
            time.sleep(2 ** attempt)

    return {"name": "", "description": ""}


def fetch_all_cwe_details(unique_cwe_ids: list[str]) -> dict[str, dict]:

    print(f"\n{'=' * 60}")
    print(f"Фаза 2: загружаем данные для {len(unique_cwe_ids)} уникальных CWE...")
    print(f"{'=' * 60}")

    session = requests.Session()
    session.headers.update({"User-Agent": "CVE-Enricher/2.0"})

    cwe_details: dict[str, dict] = {}
    for i, cwe_id in enumerate(unique_cwe_ids, 1):
        print(f"[{i}/{len(unique_cwe_ids)}] Запрашиваем {cwe_id}...")
        cwe_details[cwe_id] = fetch_cwe_info(cwe_id, session)
        time.sleep(0.3)  # небольшая пауза между запросами, чтобы не словить rate-limit

    return cwe_details


# ══════════════════════════════════════════════════════════════════════════════
# Склеиваем CVE данные с CWE деталями и сохраняем
# ══════════════════════════════════════════════════════════════════════════════

def enrich_cves():
    try:
        with open('result_task_1.json', 'r', encoding='utf-8') as f:
            cves = json.load(f)
    except FileNotFoundError:
        print("result_task_1.json не найден! Сначала запустите task_1.py.")
        return

    total = len(cves)
    print(f"Найдено {total} CVE. Используем {MAX_WORKERS} потоков для фазы 1.")

    # ── параллельное обогащение CVE ───────────────────────────────
    print(f"\n{'=' * 60}")
    print("Фаза 1: обогащение CVE (MITRE CVE API + NVD)...")
    print(f"{'=' * 60}")

    enriched: list[dict | None] = [None] * total

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_idx = {
            executor.submit(enrich_single, item, i + 1, total): i
            for i, item in enumerate(cves)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                enriched[idx] = future.result()
            except Exception as e:
                print(f"  [X] Ошибка для индекса {idx}: {e}")

    enriched_cves = [e for e in enriched if e is not None]
    print(f"\nФаза 1 завершена: {len(enriched_cves)}/{total} CVE обогащено.")

    # ── последовательная загрузка CWE деталей ─────────────────────
    # Собираем все уникальные CWE ID из всех CVE
    all_cwe_ids_seen: list[str] = []
    for cve in enriched_cves:
        for cwe_id in cve.get('cwe_ids', []):
            if cwe_id not in all_cwe_ids_seen:
                all_cwe_ids_seen.append(cwe_id)

    cwe_details_map: dict[str, dict] = {}
    if all_cwe_ids_seen:
        cwe_details_map = fetch_all_cwe_details(all_cwe_ids_seen)
    else:
        print("\nНет CWE ID для загрузки.")

    # ── склеиваем и формируем финальный результат ─────────────────
    print(f"\n{'=' * 60}")
    print("Фаза 3: сборка финального результата...")
    print(f"{'=' * 60}")

    result = []
    for cve in enriched_cves:
        cwe_ids = cve.pop('cwe_ids', [])  # убираем временное поле

        # Строим словарь cwe: {cwe_id: {name, description}}
        cwe_dict = {}
        for cwe_id in cwe_ids:
            cwe_dict[cwe_id] = cwe_details_map.get(cwe_id, {"name": "", "description": ""})

        cve['cwe'] = cwe_dict
        result.append(cve)

    with open('result_task_2.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    print(f"Готово. Сохранено {len(result)} записей в result_task_2.json")
    print(f"Уникальных CWE загружено: {len(cwe_details_map)}")


if __name__ == "__main__":
    print("Starting Task 2...")
    enrich_cves()