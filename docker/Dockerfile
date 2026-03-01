FROM python:3.11-slim

RUN pip install --no-cache-dir pymumble

WORKDIR /app
COPY channel_bot.py .

EXPOSE 4378/udp

ENTRYPOINT ["python3", "channel_bot.py"]
