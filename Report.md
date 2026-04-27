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

## Задача 2: Обогащение данных через MITRE API
Полученные идентификаторы прогонялись через публичное API CVE: `https://cveawg.mitre.org/api/cve/`.

**Инструменты:** Библиотека `requests`, встроенные модули `json` и `datetime`.
**Сложности:** MITRE возвращает JSON версии 5 (CNA Container), у которого более сложная вложенная структура, а точные строки CPE (cpe:2.3:a:...) там формируются не всегда в явном виде. 
**Решение:** Строка CPE формировалась на основе данных из поля `affected` (из атрибутов `vendor`, `product` и `version`) программным путем. Вектора CVSS извлекались из `metrics`.

{
        "ID": "CVE-2026-28950",
        "vendor_release_date": "2026-04-27T06:12:11.790000Z",
        "vendor_release_url": "https://support.apple.com/en-us/127002",
        "url": "https://www.cve.org/CVERecord?id=CVE-2026-28950",
        "published_date": "2026-04-22T18:22:39.313Z",
        "updated_date": "2026-04-23T20:12:34.310Z",
        "description": "A logging issue was addressed with improved data redaction. This issue is fixed in iOS 18.7.8 and iPadOS 18.7.8, iOS 26.4.2 and iPadOS 26.4.2. Notifications marked for deletion could be unexpectedly retained on the device.",
        "cvss_list": [
            {
                "version": "cvssv31",
                "score": 6.2,
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "MEDIUM"
            }
        ],
        "cpe_list": [
            "cpe:2.3:a:apple:ios_and_ipados:unspecified:*:*:*:*:*:*:*"
        ],
        "cwe": {}
    }
}
## Задача 3: Конвертация JSON в XML
Необходимо было переложить сложную структуру с CVSS, CPE и CWE в формат XML с сохранением родительских тегов и переносом данных в атрибуты.

**Инструменты:** Встроенная библиотека `xml.etree.ElementTree` и `xml.dom.minidom` (для pretty-print отступов).
**Сложности:** В некоторых CWE-названиях могли попадаться спецсимволы вроде угловых скобок (`<`, `>`), которые ломают парсер XML.
**Решение:** Добавлена очистка названий (name) от запрещенных для XML-символов перед сохранением в атрибуты.

<vulnerability>
<ID>CVE-2026-28950</ID>
<vendor_release_date>2026-04-27T06:12:11.790000Z</vendor_release_date>
<vendor_release_url>https://support.apple.com/en-us/127002</vendor_release_url>
<url>https://www.cve.org/CVERecord?id=CVE-2026-28950</url>
<published_date>2026-04-22T18:22:39.313Z</published_date>
<updated_date>2026-04-23T20:12:34.310Z</updated_date>
<description>A logging issue was addressed with improved data redaction. This issue is fixed in iOS 18.7.8 and iPadOS 18.7.8, iOS 26.4.2 and iPadOS 26.4.2. Notifications marked for deletion could be unexpectedly retained on the device.</description>
<cvss_list>
<cvss version="cvssv31" score="6.2" severity="MEDIUM">CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</cvss>
</cvss_list>
<cpe_list>
<cpe>cpe:2.3:a:apple:ios_and_ipados:unspecified:*:*:*:*:*:*:*</cpe>
</cpe_list>
<cwe_list/>
</vulnerability>
