FROM python:3.11-slim

WORKDIR /app

# Copia requirements
COPY python-analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia el modelo compartido
COPY shared ./shared

# Copia el analizador
COPY python-analyzer . .

EXPOSE 5000

CMD ["python", "main.py"]
