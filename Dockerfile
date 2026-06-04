FROM python:3.12-slim

WORKDIR /app

# System dependency for curl (used as fallback in some HTTP calls)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY task_1.py task_2.py task_3.py task_4.py fill_db.py json_schema.json ./

# Default: run all tasks sequentially (tasks 1-4)
# For task 5 (DB fill) run fill_db.py separately after DB is up
CMD ["bash", "-c", \
     "python task_1.py && python task_2.py && python task_3.py && python task_4.py"]
