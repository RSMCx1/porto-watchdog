FROM python:3.9-slim

RUN apt-get update && apt-get install -y --no-install-recommends libopus0 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pymumble protobuf

WORKDIR /app
COPY channel_bot.py .

EXPOSE 4378/udp

ENTRYPOINT ["python3", "channel_bot.py"]
