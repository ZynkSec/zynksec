import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: [
      "**/node_modules/**",
      "**/.next/**",
      "**/dist/**",
      "**/build/**",
      "**/.venv/**",
      "**/__pycache__/**",
      "**/.turbo/**",
    ],
  },
  js.configs.recommended,
  {
    files: ["apps/**/*.{js,mjs,cjs,jsx}", "packages/**/*.{js,mjs,cjs,jsx}"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
];
