New-Item -ItemType Directory -Path C:\Script -Force
Invoke-WebRequest https://raw.githubusercontent.com/chakujy/testmkdp/main/autopilot.ps1 `
  -UseBasicParsing `
  -OutFile C:\Script\autopilot.ps1
