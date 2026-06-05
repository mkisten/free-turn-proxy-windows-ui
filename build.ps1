$ErrorActionPreference = "Stop"

python -m PyInstaller `
  --noconfirm `
  --onedir `
  --windowed `
  --name FreeTurnProxyWindowsClient `
  app.py
