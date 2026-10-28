export async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !(options.body instanceof FormData))
    headers.set("Content-Type", "application/json");
  let response: Response;
  try {
    response = await fetch(path, { ...options, headers });
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error(
        "Cannot reach the Ghidrama server. Make sure it is running, then reload this page and try again.",
      );
    }
    throw error;
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = await response.json();
      if (typeof payload.detail === "string") message = payload.detail;
      else if (Array.isArray(payload.detail))
        message = payload.detail
          .map((error: { msg?: string }) => error.msg)
          .join("; ");
      else if (payload.message) message = payload.message;
    } catch {
      /* The server may return a non-JSON gateway error. */
    }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export const errorMessage = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "Something went wrong. Please try again.";
export const providerName = (id: string) =>
  id === "ollama" ? "Ollama Cloud" : "OpenRouter";
export const sizeLabel = (bytes: number) =>
  bytes < 1024
    ? `${bytes} B`
    : bytes < 1024 ** 2
      ? `${(bytes / 1024).toFixed(1)} KB`
      : `${(bytes / 1024 ** 2).toFixed(1)} MB`;
export const formatTime = (value: string) =>
  new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
