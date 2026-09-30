# Minimal container for the SkillGuard MCP server (stdio transport).
# No npm dependencies to install; git is required because the scanner clones
# git/GitHub targets (shallow, with hooks disabled) before statically reading them.
FROM node:22-alpine
RUN apk add --no-cache git
WORKDIR /app
# index.js loads ./report.js for --report and --show-report. mcp.js does not.
# report.schema.json is not read by the CLI, so the image copy list does not add it.
COPY package.json index.js mcp.js report.js ./
# Speaks MCP over stdio; run with: docker run -i <image>
ENTRYPOINT ["node", "mcp.js"]
