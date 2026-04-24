export interface RuntimeEnv {
  apiUrl: string;
  apiKey: string;
}

const DEFAULT_API_URL = "http://127.0.0.1:3000";

export function getRuntimeEnv(): RuntimeEnv {
  if (typeof window === "undefined") {
    return {
      apiUrl: process.env.API_URL || DEFAULT_API_URL,
      apiKey: process.env.API_KEY || "",
    };
  }

  const raw = document.body?.dataset.env;
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as Partial<RuntimeEnv>;
      return {
        apiUrl: parsed.apiUrl || DEFAULT_API_URL,
        apiKey: parsed.apiKey || "",
      };
    } catch {
      // fall through to defaults
    }
  }

  return { apiUrl: DEFAULT_API_URL, apiKey: "" };
}
