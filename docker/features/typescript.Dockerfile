# claude-feat: typescript
# claude-feat-md: TypeScript: typescript-language-server and tsc 6, a project's own typescript in node_modules is used when it has one
# claude-feat-lsp: {"typescript": {"command": "typescript-language-server", "args": ["--stdio"], "extensionToLanguage": {".ts": "typescript", ".tsx": "typescriptreact", ".js": "javascript", ".jsx": "javascriptreact", ".mts": "typescript", ".cts": "typescript", ".mjs": "javascript", ".cjs": "javascript"}}}

# From npm. The server drives tsserver, which TypeScript 7, the native
# rewrite, no longer ships: with 7 the server starts and answers nothing. So
# TypeScript stays on 6 and is not refreshed by update-pins.py, move it by
# hand once the server supports 7. It is only the fallback anyway, the
# server prefers the typescript of the project it is opened in.
ARG TYPESCRIPT_LANGUAGE_SERVER_VERSION=6.1.0
RUN npm install -g \
    "typescript-language-server@${TYPESCRIPT_LANGUAGE_SERVER_VERSION}" \
    typescript@6.0.3 \
    && npm cache clean --force
