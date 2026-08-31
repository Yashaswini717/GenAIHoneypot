# Dashboard dev server.
#
# This file was committed empty, which is why `docker compose up frontend`
# failed with "the Dockerfile cannot be empty" and the dashboard could never
# start.
#
# Development image on purpose: compose mounts ./frontend over /app and runs
# `npm run dev -- --host`, so Vite serves with hot reload and the source on
# the host is the source being served. Building a static bundle here would be
# overwritten by that mount.

FROM node:20-alpine

WORKDIR /app

# Dependencies are installed into the image, then compose masks /app with the
# host mount and keeps /app/node_modules as an anonymous volume — which is why
# node_modules must exist in the image for the mount to shadow around it.
COPY package.json ./
COPY package-lock.json* ./

# `npm ci` needs a lockfile; this repo does not commit one (it was removed in
# "fix: remove root package-lock from tracking"), so fall back to install.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY . .

EXPOSE 5173

# --host is what makes Vite listen on 0.0.0.0 instead of localhost inside the
# container. Without it the port is published but nothing answers on it.
CMD ["npm", "run", "dev", "--", "--host"]
