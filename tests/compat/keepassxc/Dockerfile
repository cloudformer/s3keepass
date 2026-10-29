# The reference for the compatibility tests: KeePassXC's keepassxc-cli, plus Node to run the web UI's crypto
# path (tests/compat/kdbx_node.js) next to it. The repository is mounted at /repo (docker-compose.yml).
FROM node:22-alpine3.21
RUN apk add --no-cache keepassxc \
 && npm install -g @xmldom/xmldom@0.7.13
ENV NODE_PATH=/usr/local/lib/node_modules QT_QPA_PLATFORM=offscreen
CMD ["sleep", "infinity"]
