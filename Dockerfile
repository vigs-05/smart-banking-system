# ---------- build stage ----------
FROM ubuntu:24.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ libsqlite3-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY httplib.h json.hpp server.cpp ./
RUN g++ -std=c++17 -O2 -pthread server.cpp -o bank -lsqlite3

# ---------- run stage (small image) ----------
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/bank ./
COPY public ./public
EXPOSE 8080
CMD ["./bank", "--seed"]
