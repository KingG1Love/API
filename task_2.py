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

# Настройки потоков
MAX_WORKERS_CVE = 8  # Для сбора CVE
MAX_WORKERS_CWE = 5  # Для сбора CWE
NVD_RETRY_WAIT = 7

# ── Thread-local session ───────────────────────────────────────────────────────
_local = threading.local()


def get_session() -> requests.Session:
    if not hasattr(_local, 'session'):
        s = requests.Session()
        s.headers.update({"User-Agent": "CVE-Enricher/2.1"})
        _local.session = s
    return _local.session


# ══════════════════════════════════════════════════════════════════════════════
# Обогащение CVE и генерация CPE
# ══════════════════════════════════════════════════════════════════════════════

def expand_cpe_range(base_cpe: str, end_version: str, is_excluding: bool) -> list[str]:
    """
    Разворачивает диапазон до конкретной версии (end_version) в список CPE
    в рамках одной мажорной версии.
    Пример: end_version="16.4.1" -> генерирует версии 16.0, 16.1, 16.2, 16.3, 16.4.
    """
    expanded = []
    parts = end_version.split('.')

    # Если версия не похожа на стандартную X.Y (например, просто строка или дата),
    # возвращаем базовый CPE с припиской.
    if not (len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit()):
        return [f"{base_cpe} (до {end_version})"]

    major = parts[0]
    minor = int(parts[1])

    cpe_parts = base_cpe.split(':')

    def make_cpe(ver: str) -> str:

        if len(cpe_parts) >= 6 and cpe_parts[5] == '*':
            new_cpe = list(cpe_parts)
            new_cpe[5] = ver
            return ':'.join(new_cpe)
        return f"{base_cpe} (v{ver})"

    # Генерируем минорные версии от 0 до minor-1
    for m in range(minor):
        expanded.append(make_cpe(f"{major}.{m}"))

    # Если 'Including', то последняя минорная версия тоже уязвима
    if not is_excluding:
        expanded.append(make_cpe(f"{major}.{minor}"))
    # Если 'Excluding', но есть патч-версия (например, исправление в 16.4.1),
    # значит вся ветка 16.4.0 была уязвима, добавляем 16.4
    elif is_excluding and len(parts) >= 3 and parts[2].isdigit() and int(parts[2]) > 0:
        expanded.append(make_cpe(f"{major}.{minor}"))

    return expanded


def fetch_from_nvd(cve_id: str) -> tuple[list, list]:
    """Возвращает (cpe_list, cwe_ids) из NVD API 2.0."""
    for attempt in range(3):
        try:
            resp = get_session().get(NVD_CVE_URL.format(cve_id=cve_id), timeout=20)
            if resp.status_code == 200:
                break
            if resp.status_code == 429:
                time.sleep(NVD_RETRY_WAIT)
                continue
            return [], []
        except Exception:
            return [], []
    else:
        return [], []

    vulns = resp.json().get('vulnerabilities', [])
    if not vulns:
        return [], []

    cve_data = vulns[0].get('cve', {})
    cpe_entries = []

    for config in cve_data.get('configurations', []):
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if not match.get('vulnerable', False):
                    continue

                cpe = match.get('criteria', '')
                if not cpe:
                    continue


                if match.get('versionEndExcluding'):
                    cpe_entries.extend(expand_cpe_range(cpe, match['versionEndExcluding'], True))
                elif match.get('versionEndIncluding'):
                    cpe_entries.extend(expand_cpe_range(cpe, match['versionEndIncluding'], False))
                else:
                    cpe_entries.append(cpe)

    cwe_ids = []
    for w in cve_data.get('weaknesses', []):
        for desc in w.get('description', []):
            val = desc.get('value', '')
            if re.match(r'^CWE-\d+$', val) and val not in cwe_ids:
                cwe_ids.append(val)


    return list(dict.fromkeys(cpe_entries)), cwe_ids


def enrich_single(item: dict, index: int, total: int) -> dict | None:
    cve_id = item['ID']
    print(f"[{index}/{total}] Обрабатываем {cve_id}...")

    try:
        resp = get_session().get(MITRE_CVE_URL.format(cve_id=cve_id), timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception:
        return None

    meta = data.get('cveMetadata', {})
    containers = data.get('containers', {})
    cna = containers.get('cna', {})

    descs = cna.get('descriptions', [])
    desc_text = next((d.get('value', '') for d in descs if d.get('lang', '').startswith('en')),
                     descs[0].get('value', '') if descs else '')

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

    cpe_list, cwe_ids_nvd = fetch_from_nvd(cve_id)
    all_cwe_ids = list(dict.fromkeys(cwe_ids_mitre + cwe_ids_nvd))

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
        "cwe_ids": all_cwe_ids,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Загрузка деталей CWE (Параллельно)
# ══════════════════════════════════════════════════════════════════════════════

def fetch_cwe_info(cwe_id: str) -> dict:
    """Запрашивает MITRE CWE API для одного CWE ID."""
    num = re.sub(r'\D', '', cwe_id)
    url = CWE_API_URL.format(cwe_num=num)
    session = get_session()

    for attempt in range(4):
        try:
            resp = session.get(url, timeout=15)

            if resp.status_code == 404:
                return {"name": "", "description": ""}

            if resp.status_code == 429:
                time.sleep(3 * (attempt + 1))
                continue

            if resp.status_code != 200:
                time.sleep(2 ** attempt)
                continue

            data = resp.json()
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
                return {"name": "", "description": ""}

            w = items[0]
            name = w.get('@Name') or w.get('Name') or w.get('@name') or w.get('name') or ''

            def extract_text(node):
                if isinstance(node, dict):
                    return node.get('#text') or node.get('text') or node.get('_text') or ''
                elif isinstance(node, list):
                    return " ".join([extract_text(n) for n in node])
                else:
                    return str(node)

            raw_desc = w.get('Description') or w.get('description') or ''
            desc = extract_text(raw_desc).strip()

            if not desc:
                raw_ext = w.get('Extended_Description') or w.get('extended_description') or ''
                desc = extract_text(raw_ext).strip()

            print(f"  [CWE-API] Загружено {cwe_id} -> {name[:30]}...")
            return {"name": name, "description": desc}

        except Exception:
            time.sleep(2 ** attempt)

    return {"name": "", "description": ""}


def fetch_all_cwe_details(unique_cwe_ids: list[str]) -> dict[str, dict]:
    """Параллельно загружает данные для уникальных CWE."""
    print(f"\n{'=' * 60}")
    print(f"Загружаем данные для {len(unique_cwe_ids)} уникальных CWE (Многопоточно)...")
    print(f"{'=' * 60}")

    cwe_details: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CWE) as executor:
        future_to_cwe = {
            executor.submit(fetch_cwe_info, cwe_id): cwe_id
            for cwe_id in unique_cwe_ids
        }

        for future in as_completed(future_to_cwe):
            cwe_id = future_to_cwe[future]
            try:
                cwe_details[cwe_id] = future.result()
            except Exception as e:
                print(f"  [X] Ошибка при парсинге {cwe_id}: {e}")
                cwe_details[cwe_id] = {"name": "", "description": ""}

    return cwe_details


# ══════════════════════════════════════════════════════════════════════════════
# Сборка и сохранение
# ══════════════════════════════════════════════════════════════════════════════

def enrich_cves():
    try:
        with open('result_task_1.json', 'r', encoding='utf-8') as f:
            cves = json.load(f)
    except FileNotFoundError:
        print("result_task_1.json не найден! Сначала запустите task_1.py.")
        return

    total = len(cves)
    print(f"\n{'=' * 60}")
    print(f"Обогащение {total} CVE (MITRE CVE API + NVD)...")
    print(f"{'=' * 60}")

    enriched: list[dict | None] = [None] * total

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CVE) as executor:
        future_to_idx = {
            executor.submit(enrich_single, item, i + 1, total): i
            for i, item in enumerate(cves)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                enriched[idx] = future.result()
            except Exception as e:
                pass

    enriched_cves = [e for e in enriched if e is not None]

    # Собираем уникальные CWE
    all_cwe_ids_seen = []
    for cve in enriched_cves:
        for cwe_id in cve.get('cwe_ids', []):
            if cwe_id not in all_cwe_ids_seen:
                all_cwe_ids_seen.append(cwe_id)


    cwe_details_map = fetch_all_cwe_details(all_cwe_ids_seen) if all_cwe_ids_seen else {}

    print(f"\n{'=' * 60}")
    print("Сборка финального результата...")
    print(f"{'=' * 60}")

    result = []
    for cve in enriched_cves:
        cwe_ids = cve.pop('cwe_ids', [])
        cwe_dict = {}
        for cwe_id in cwe_ids:
            cwe_dict[cwe_id] = cwe_details_map.get(cwe_id, {"name": "", "description": ""})

        cve['cwe'] = cwe_dict
        result.append(cve)

    with open('result_task_2.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    print(f"Готово. Сохранено {len(result)} записей в result_task_2.json")


if __name__ == "__main__":
    enrich_cves()