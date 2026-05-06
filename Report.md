Отчет по лабораторной работе №2 «Сбор данных об уязвимостях»

Белимов Адрей Олегович


## Задача 1: Парсинг вендора
В качестве поставщика ПО была выбрана компания Apple. Источником данных послужила страница: `https://support.apple.com/en-us/HT201222`.

**Инструменты:** Язык Python, библиотеки `requests` и `beautifulsoup4`.
**Сложности:** Страница Apple не содержит прямых CVE-идентификаторов в главной таблице — она лишь содержит ссылки на отдельные релизы. 
**Решение:** Был реализован переход по ссылкам свежих обновлений (в скрипте задан лимит в 5 последних статей) и поиск CVE с помощью регулярных выражений (`CVE-\d{4}-\d{4,7}`) в тексте самих статей-уведомлений.

{
        "ID": "CVE-2026-28950",
        "vendor_release_date": "2026-04-27T06:12:11.790000Z",
        "vendor_release_url": "https://support.apple.com/en-us/127002"
},

## Задача 2: Обогащение данных через MITRE API и NVD API
Полученные идентификаторы прогонялись через публичное API CVE: `https://cveawg.mitre.org/api/cve/`, `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=`

**Инструменты:** Библиотека `requests`, встроенные модули `json` и `datetime`.
**Сложности:** MITRE возвращает JSON версии 5 (CNA Container), у которого более сложная вложенная структура, а точные строки CPE (cpe:2.3:a:...) там формируются не всегда в явном виде. 
**Решение:** Строка CPE формировалась на основе данных из поля `affected` (из атрибутов `vendor`, `product` и `version`) программным путем. Вектора CVSS извлекались из `metrics`.

{
        "ID": "CVE-2026-20639",
        "vendor_release_date": "2026-05-06T04:25:10Z",
        "vendor_release_url": "https://support.apple.com/en-us/126795",
        "url": "https://www.cve.org/CVERecord?id=CVE-2026-20639",
        "published_date": "2026-03-25T00:32:30.351Z",
        "updated_date": "2026-04-02T18:20:46.356Z",
        "description": "An integer overflow was addressed with improved input validation. This issue is fixed in macOS Sequoia 15.7.5, macOS Sonoma 14.8.5, macOS Tahoe 26.3. Processing a maliciously crafted string may lead to heap corruption.",
        "cvss_list": [
            {
                "version": "cvssv31",
                "score": 7.5,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "severity": "HIGH"
            }
        ],
        "cpe_list": [
            "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:* (>=14.0, <14.8.5)",
            "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:* (>=15.0, <15.7.5)",
            "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:* (>=26.0, <26.3)"
        ],
        "cwe": {
            "CWE-190": {
                "name": "Integer Overflow or Wraparound",
                "description": "The product performs a calculation that can\n         produce an integer overflow or wraparound when the logic\n         assumes that the resulting value will always be larger than\n         the original value. This occurs when an integer value is\n         incremented to a value that is too large to store in the\n         associated representation. When this occurs, the value may\n         become a very small or negative number."
            }
        }
    },

## Задача 3: Конвертация JSON в XML
Необходимо было переложить сложную структуру с CVSS, CPE и CWE в формат XML с сохранением родительских тегов и переносом данных в атрибуты.

**Инструменты:** Встроенная библиотека `xml.etree.ElementTree` и `xml.dom.minidom` (для pretty-print отступов).
**Сложности:** В некоторых CWE-названиях могли попадаться спецсимволы вроде угловых скобок (`<`, `>`), которые ломают парсер XML.
**Решение:** Добавлена очистка названий (name) от запрещенных для XML-символов перед сохранением в атрибуты.

<vulnerability>
    <ID>CVE-2026-20651</ID>
    <vendor_release_date>2026-05-03T12:07:31Z</vendor_release_date>
    <vendor_release_url>https://support.apple.com/en-us/126795</vendor_release_url>
    <url>https://www.cve.org/CVERecord?id=CVE-2026-20651</url>
    <published_date>2026-03-25T00:31:31.135Z</published_date>
    <updated_date>2026-04-02T18:07:21.915Z</updated_date>
    <description>A privacy issue was addressed with improved handling of temporary files. This issue is fixed in macOS Sequoia 15.7.5, macOS Sonoma 14.8.4, macOS Tahoe 26.3. An app may be able to access sensitive user data.</description>
    <cvss_list>
      <cvss version="cvssv31" score="6.2" severity="MEDIUM">CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</cvss>
    </cvss_list>
    <cpe_list>
      <cpe>cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:* (&gt;=14.0, &lt;14.8.5)</cpe>
      <cpe>cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:* (&gt;=15.0, &lt;15.7.5)</cpe>
      <cpe>cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:* (&gt;=26.0, &lt;26.3)</cpe>
    </cpe_list>
    <cwe_list>
      <cwe id="CWE-377" name="Insecure Temporary File">Creating and using insecure temporary files can leave application and system data vulnerable to attack.</cwe>
    </cwe_list>
  </vulnerability>