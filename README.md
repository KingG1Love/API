# Лабораторная работа №2: Парсинг уязвимостей Apple

Информация об обновлениях безопасности продуктов Apple и обогащение этой информации через API MITRE (cve.org).

## Инструкция по запуску

1. Установить зависимости Python:
   ```bash
   pip install -r requirements.txt
   ```
2. Выполнить скрипты последовательно:
   ```bash
   python task_1.py
   python task_2.py
   python task_3.py
   ```
Готовые файлы:
- `result_task_1.json` - Спарсченные CVE от Apple.
- `result_task_2.json` - Обогащенные данные из MITRE.
- `result_task_3.xml` - XML-формат вложенных данных.


## Структура файлов
- `task_1.py`: Парсит страницу Apple Security Advisories.
- `task_2.py`: Опрашивает MITRE API для обогащения данных CVSS, CPE, CWE.
- `task_3.py`: Преобразует JSON-данные в XML.
