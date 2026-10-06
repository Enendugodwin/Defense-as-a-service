FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY c2_web.py console.html ./
EXPOSE 8081
CMD ["python", "c2_web.py"]
