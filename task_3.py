import json
import xml.etree.ElementTree as ET
from xml.dom import minidom

def convert_to_xml():
    try:
        with open('result_task_2.json', 'r', encoding='utf-8') as f:
            cves = json.load(f)
    except FileNotFoundError:
        print("result_task_2.json not found! Run task_2.py first.")
        return

    root = ET.Element("vulnerabilities")

    for item in cves:
        cve_elem = ET.SubElement(root, "vulnerability")
        
        # 1 уровень
        fields_level_1 = ["ID", "vendor_release_date", "vendor_release_url", "url", "published_date", "updated_date", "description"]
        for key in fields_level_1:
            child = ET.SubElement(cve_elem, key)
            val = item.get(key)
            if val is not None:
                child.text = str(val).strip()
            
        # Уровень 2: cvss_list
        cvss_list_elem = ET.SubElement(cve_elem, "cvss_list")
        for cvss in item.get('cvss_list', []):
            cvss_child = ET.SubElement(cvss_list_elem, "cvss", attrib={
                "version": str(cvss.get('version', '')),
                "score": str(cvss.get('score', '')),
                "severity": str(cvss.get('severity', ''))
            })
            cvss_child.text = str(cvss.get('vector', ''))
            
        # Уровень 2: cpe_list
        cpe_list_elem = ET.SubElement(cve_elem, "cpe_list")
        for cpe in item.get('cpe_list', []):
            cpe_child = ET.SubElement(cpe_list_elem, "cpe")
            cpe_child.text = str(cpe)
            
        # Уровень 2: cwe
        cwe_list_elem = ET.SubElement(cve_elem, "cwe_list")
        cwe_dict = item.get('cwe', {})
        for cwe_id, cwe_data in cwe_dict.items():
            name = cwe_data.get('name', 'Unknown')
            # Защита от кривых XML символов
            name = str(name).replace('<', '').replace('>', '')
            cwe_child = ET.SubElement(cwe_list_elem, "cwe", attrib={
                "id": str(cwe_id),
                "name": name
            })
            cwe_child.text = str(cwe_data.get('description', ''))
            
    # Красивый вывод с отступами
    xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ", encoding="utf-8")
    
    with open("result_task_3.xml", "wb") as f:
        f.write(xmlstr)
        
    print(f"Task 3 complete. XML saved to result_task_3.xml")

if __name__ == "__main__":
    print("Starting Task 3...")
    convert_to_xml()
