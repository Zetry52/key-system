# Key System Template

Standalone template for a self-hosted license system for a Windows C++ application.

Features:
- License key validation over HTTP
- Stored user name
- Expiration date
- Key status: `active`, `frozen`, `expired`
- Strict one-device HWID binding
- Admin web panel with search
- Notes field
- Simple JSON storage
- No third-party Python dependencies

Structure:
- `server/server.py` - HTTP API, admin panel and admin CLI
- `server/licenses.json` - license storage
- `server/config.json` - admin credentials
- `client/main.cpp` - example C++ client using WinHTTP

## Server

Start the API:

```powershell
cd "C:\Users\User\Desktop\Key system\server"
python server.py serve --host 0.0.0.0 --port 8080
```

Admin panel:

```text
http://127.0.0.1:8080/admin
```

Default login:

```text
admin / changeme
```

Change admin credentials:

```powershell
python server.py set-admin --username myadmin --password mypass
```

Create a license:

```powershell
python server.py create --key ABCD-EFGH-IJKL --name Ivan --days 30 --product loader --notes "test key"
```

List licenses:

```powershell
python server.py list
```

Freeze a license:

```powershell
python server.py freeze --key ABCD-EFGH-IJKL
```

Unfreeze a license:

```powershell
python server.py unfreeze --key ABCD-EFGH-IJKL
```

Delete a license:

```powershell
python server.py delete --key ABCD-EFGH-IJKL
```

Extend a license:

```powershell
python server.py extend --key ABCD-EFGH-IJKL --days 15
```

Reset HWID:

```powershell
python server.py reset-hwid --key ABCD-EFGH-IJKL
```

## Client

Update these constants in `client/main.cpp`:
- `kServerHost`
- `kServerPort`
- `kValidatePath`
- `kProductName`

Build the client in Visual Studio as a normal console project. It uses only WinHTTP and Windows APIs.

## API

`POST /api/validate`

Request JSON:

```json
{
  "license_key": "ABCD-EFGH-IJKL",
  "hwid": "machine-id",
  "product": "loader"
}
```

Response JSON example:

```json
{
  "success": true,
  "message": "License valid",
  "name": "Ivan",
  "expires_at": "2026-04-03T12:00:00Z",
  "days_left": 30,
  "bound_hwid": "machine-id",
  "status": "active",
  "max_users": 1
}
```

## Hosting

For production, place the server behind a reverse proxy and TLS. The demo server itself is intentionally simple and meant as a starting point.
