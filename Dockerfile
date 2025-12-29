FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt requirements_extra.txt /app/
RUN python -m pip install --no-cache-dir -r requirements.txt -r requirements_extra.txt

COPY . /app

ENV MONOLITH_HOST=0.0.0.0
ENV MONOLITH_PORT=5000

EXPOSE 5000

CMD ["python3", "cyber.py"]
