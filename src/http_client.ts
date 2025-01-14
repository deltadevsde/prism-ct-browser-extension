/**
 * Abstract base class for making HTTP requests.
 * Provides core functionality for making GET and POST requests with JSON payloads.
 */
export abstract class HttpClient {
  /**
   * The base URL that will be prepended to all request endpoints
   */
  protected baseUrl: URL;

  /**
   * Creates a new HttpClient instance
   * @param baseUrl - The base URL as either a string or URL object
   */
  constructor(baseUrl: string | URL) {
    this.baseUrl = new URL(baseUrl);
  }

  /**
   * Updates the base URL used for all requests
   * @param baseUrl - The new base URL as either a string or URL object
   */
  setBaseUrl(baseUrl: string | URL) {
    this.baseUrl = new URL(baseUrl);
  }

  /**
   * Constructs a full URL from the base URL, endpoint, and query parameters
   * @param endpoint - The API endpoint path
   * @param queryParams - Object containing query string parameters
   * @returns Constructed URL object
   * @private
   */
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

  /**
   * Makes a GET request and parses the JSON response
   * @param endpoint - The API endpoint path
   * @param queryParams - Optional query string parameters
   * @returns Promise resolving to the parsed JSON response
   * @throws Error if the request fails or response is not OK
   */
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

  /**
   * Makes a POST request with a JSON body and parses the JSON response
   * @param endpoint - The API endpoint path
   * @param body - The request body that will be serialized to JSON
   * @param queryParams - Optional query string parameters
   * @returns Promise resolving to the parsed JSON response
   * @throws Error if the request fails or response is not OK
   */
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
