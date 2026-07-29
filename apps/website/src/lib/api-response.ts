export async function readJsonResponse(response: Response): Promise<unknown> {
  const contentType = response.headers
    .get("Content-Type")
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase();
  if (contentType !== "application/json") return undefined;

  try {
    return await response.json();
  } catch {
    return undefined;
  }
}
