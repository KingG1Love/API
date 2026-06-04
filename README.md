# Лабораторная работа №2: Парсинг уязвимостей Apple

Источник данных: **Apple Security Advisories** — https://support.apple.com/en-us/HT201222

## Структура файлов

| Файл | Описание |
|------|----------|
| `task_1.py` | Задача 1: Парсинг CVE со страницы Apple Security Advisories |
| `task_2.py` | Задача 2: Обогащение данных через MITRE CVE API и NVD API |
| `task_3.py` | Задача 3: Конвертация result_task_2.json → result_task_3.xml |
| `task_4.py` | Задача 4: Валидация result_task_2.json по json_schema.json |
| `fill_db.py` | Задача 5: Заполнение PostgreSQL из result_task_2.json |
| `json_schema.json` | JSON Schema для валидации |
| `sql/schema.sql` | DDL-скрипт создания таблиц |
| `docker-compose.yml` | Docker Compose для PostgreSQL |
| `Dockerfile` | Docker-образ для запуска задач|
| `requirements.txt` | Python-зависимости |

---

## Локальный запуск (без Docker)

### 1. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 2. Выполнение задач по порядку

```bash
python task_1.py   # → result_task_1.json
python task_2.py   # → result_task_2.json
python task_3.py   # → result_task_3.xml
python task_4.py   # валидация result_task_2.json
```

### 3. База данных

Поднять PostgreSQL:
```bash
docker compose up -d postgres
# дождаться healthy
docker compose ps
```

Заполнить БД:
```bash
DB_URL=postgresql://postgres:qwe123@localhost:5432/laba2 python fill_db.py
```

---

## Запуск через Docker

```bash
# Собрать образ
docker build -t lab2-parser .

# Запустить (результаты появятся в контейнере)
docker run --rm -v "$(pwd)/output:/app" lab2-parser
```

> Результирующие файлы (`result_task_1.json`, `result_task_2.json`, `result_task_3.xml`)
> будут смонтированы в `./output/`.



## Полный запуск через Docker Compose

```bash
# 1. Поднять PostgreSQL
docker compose up -d postgres

# 2. Запустить парсер
docker build -t lab2-parser .
docker run --rm \
  --network host \
  -v "$(pwd)/output:/app" \
  lab2-parser

# 3. Заполнить БД
docker run --rm \
  --network host \
  -v "$(pwd)/output/result_task_2.json:/app/result_task_2.json:ro" \
  -e DB_URL=postgresql://postgres:qwe123@localhost:5432/laba2 \
  lab2-parser \
  python fill_db.py
```