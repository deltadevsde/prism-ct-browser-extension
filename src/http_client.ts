export abstract class HttpClient {
  protected baseUrl: URL;

  constructor(baseUrl: string | URL) {
    this.baseUrl = new URL(baseUrl);
  }

  setBaseUrl(baseUrl: string | URL) {
    this.baseUrl = new URL(baseUrl);
  }

  private constructUrl(
    endpoint: string,
    queryParams: Record<string, string | number>,
  ): URL {
    const url = new URL(this.baseUrl);
    url.pathname = [url.pathname, endpoint].join("/").replace(/\/+/g, "/");
    for (const [key, value] of Object.entries(queryParams)) {
      url.searchParams.append(key, value.toString());
    }
    return url;
  }

  protected async fetchJson<T>(
    endpoint: string,
    queryParams: Record<string, string | number> = {},
  ): Promise<T> {
    const url = this.constructUrl(endpoint, queryParams);
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`Http request failed: ${response.statusText}`);
    }

    return await response.json();
  }

  protected async postJson<T>(
    endpoint: string,
    body: object,
    queryParams: Record<string, string | number> = {},
  ): Promise<T> {
    const url = this.constructUrl(endpoint, queryParams);
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`Http request failed: ${response.statusText}`);
    }

    return await response.json();
  }
}
