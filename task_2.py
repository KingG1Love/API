import json
import requests

def enrich_cves():
    try:
        with open('result_task_1.json', 'r', encoding='utf-8') as f:
            cves = json.load(f)
    except FileNotFoundError:
        print("result_task_1.json not found! Run task_1.py first.")
        return

    enriched_data = []
    total = len(cves)
    print(f"Found {total} CVEs to enrich.")

    for i, item in enumerate(cves, 1):
        cve_id = item['ID']
        print(f"[{i}/{total}] Fetching {cve_id} from MITRE...")
        
        # Public MITRE API endpoint for single CVE
        api_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        
        try:
            resp = requests.get(api_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                
                # Извлекаем метаданные
                cve_metadata = data.get('cveMetadata', {})
                published_date = cve_metadata.get('datePublished', '')
                updated_date = cve_metadata.get('dateUpdated', '')
                
                containers = data.get('containers', {})
                cna = containers.get('cna', {})
                
                # URL до cve.org
                url_to_cve_org = f"https://www.cve.org/CVERecord?id={cve_id}"
                
                # Описание
                descriptions = cna.get('descriptions', [])
                desc_text = ""
                if descriptions:
                    desc_text = descriptions[0].get('value', '')
                    if not desc_text and 'description' in descriptions[0]:
                        desc_text = descriptions[0]['description']
                
                # CVSS
                cvss_list = []
                adp = containers.get('adp', [])
                for dp in adp:
                    for metric in dp.get('metrics', []):
                        for cvss_key in ['cvssV3_1', 'cvssV3_0', 'cvssV2']:
                            if cvss_key in metric:
                                cvss_data = metric[cvss_key]
                                cvss_list.append({
                                    "version": cvss_key.lower().replace('_', ''),
                                    "score": cvss_data.get('baseScore', 0),
                                    "vector": cvss_data.get('vectorString', ''),
                                    "severity": cvss_data.get('baseSeverity', cvss_data.get('severity', 'UNKNOWN'))
                                })
                                
                # CPE (Если не находим точную строку, парсим из affected products)
                cpe_list = []
                affected = cna.get('affected', [])
                for aff in affected:
                    vendor = aff.get('vendor', 'Unknown').lower()
                    product = aff.get('product', 'Unknown').lower().replace(' ', '_')
                    for ver in aff.get('versions', []):
                        v = ver.get('version', 'unspecified')
                        cpe_list.append(f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*")
                        
                # CWE
                cwe_dict = {}
                problem_types = cna.get('problemTypes', [])
                for pt in problem_types:
                    for desc in pt.get('descriptions', []):
                        # Может быть тип CWE
                        if "cwe" in desc.get('type', '').lower() or "cwe" in desc.get('description', '').lower():
                            cwe_id_raw = desc.get('cweId', '')
                            # Если cweId пустой, возможно он втексте
                            if not cwe_id_raw and 'CWE-' in desc.get('description', ''):
                                cwe_id_raw = desc.get('description').split()[0]
                            
                            cwe_dict[cwe_id_raw] = {
                                "name": desc.get('description', ''),
                                "description": desc.get('description', '')
                            }
                            
                enriched_data.append({
                    "ID": cve_id,
                    "vendor_release_date": item.get('vendor_release_date'),
                    "vendor_release_url": item.get('vendor_release_url'),
                    "url": url_to_cve_org,
                    "published_date": published_date,
                    "updated_date": updated_date,
                    "description": desc_text,
                    "cvss_list": cvss_list,
                    "cpe_list": list(set(cpe_list)),
                    "cwe": cwe_dict
                })
            else:
                print(f"  [!] Failed to fetch {cve_id}. API responded with {resp.status_code}")
        except Exception as e:
            print(f"  [X] Error fetching {cve_id}: {e}")

    # Сохраняем результат
    with open('result_task_2.json', 'w', encoding='utf-8') as f:
        json.dump(enriched_data, f, indent=4, ensure_ascii=False)
        
    print(f"Task 2 complete. Saved {len(enriched_data)} items to result_task_2.json")

if __name__ == "__main__":
    print("Starting Task 2...")
    enrich_cves()
