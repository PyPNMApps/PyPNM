# System Operations - PyPNM System Web Service Reload

Trigger A Hot Reload Of The PyPNM FastAPI Service During Development.

## Table Of Contents

- [Overview](#overview)
- [Endpoint](#endpoint)
- [Request](#request)
- [Response](#response)
- [Notes](#notes)
- [Field Tables](#field-tables)

## Overview

The PyPNM System Web Service Reload endpoint provides a lightweight way to signal a hot reload of the FastAPI application when it is running with an auto-reload process manager (for example, `uvicorn --reload`).

Internally, the endpoint touches the route module file to update its timestamp. When `uvicorn` (or an equivalent server) is configured with reload enabled, this file-change event triggers a code reload. This is intended primarily for development and test environments, not for production.

## Endpoint

`GET /pypnm/system/webService/reload`

## Request

No request body or query parameters are required.

The endpoint follows whatever global middleware you have configured for the API (authentication, logging, CORS, etc.).

### Example Request (cURL)

```bash
curl -X GET "http://127.0.0.1:8000/pypnm/system/webService/reload"
```

If your service is exposed via HTTPS or a different interface/port, adjust the URL accordingly, for example:

```bash
curl -X GET "https://pypnm.example.net:443/pypnm/system/webService/reload"
```

## Response

On success, the endpoint returns a small JSON object indicating that the reload trigger was issued. It does not wait for or validate that the reload has completed; it only reports whether the file-touch operation succeeded.

### Successful Response

**Status:** `200 OK`  
**Body (JSON):**

```json
{
  "status": "reload triggered"
}
```

### Error Responses

If the underlying file-touch operation fails (for example, due to filesystem permissions or an unexpected runtime error), a `500 Internal Server Error` is returned with a JSON payload.

**Status:** `500 Internal Server Error`  
**Body (JSON):**

```json
{
  "detail": "Failed to trigger reload: <reason from underlying exception>"
}
```

The exact error message will depend on the underlying exception encountered while attempting to touch the route file.

## Notes

- This endpoint relies on the application being started with an auto-reload mechanism such as:

  ```bash
  pypnm serve --reload
  ```

  or:

  ```bash
  uvicorn pypnm.main:app --reload
  ```

  Without `--reload` (or an equivalent setting), touching the file will have no practical effect on a running production process.

- The endpoint should generally be restricted to trusted users and non-production environments, as it influences application behavior and may cause transient unavailability during reloads.

- The reload mechanism is implemented by updating the timestamp of the current route module:

  - If the file-touch operation succeeds, `"status": "reload triggered"` is returned.
  - If it fails, a `500` with an error detail is returned.

## Field Tables

The response is a simple JSON object rather than a complex analysis payload. The contract is:

| Element       | Type   | Description                                      |
| ------------- | ------ | ------------------------------------------------ |
| HTTP method   | `GET`  | Read-only signal that attempts to trigger reload |
| URL path      | string | `/pypnm/system/webService/reload`               |
| Response body | object | JSON object with a `status` field.              |

### Response Body Fields

| Field  | Type   | Description                                                  |
| ------ | ------ | ------------------------------------------------------------ |
| status | string | `"reload triggered"` on success, or an error status message. |
