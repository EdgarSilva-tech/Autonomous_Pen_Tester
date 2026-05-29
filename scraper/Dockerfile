# Official Playwright image — ships with Chromium, Firefox, WebKit pre-installed.
# We only install what we need on top.
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

ENV PORT=9222
EXPOSE 9222

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9222"]
