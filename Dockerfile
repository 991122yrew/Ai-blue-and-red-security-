FROM python:3.12-slim
WORKDIR /app
COPY index.html live.html ./
COPY server ./server
ENV HOST=0.0.0.0 PORT=8000
EXPOSE 8000
CMD ["python", "server/app.py"]
