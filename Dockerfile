FROM python:3.11-slim

RUN pip install --no-cache-dir pymumble

WORKDIR /app
COPY channel_bot.py .
COPY bot_config.ini .

EXPOSE 4378/udp

ENTRYPOINT ["python3", "channel_bot.py"]
CMD ["-c", "/app/bot_config.ini"]
