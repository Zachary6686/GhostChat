# GhostChat full validation: Python check, deps hint, then run test stages with PASS/FAIL summary.
# Run from repository root (ghostchat/): .\scripts\validate_all.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Resolve-Path (Join-Path $ScriptDir "..")
Set-Location $Root

Write-Host "=== GhostChat validation (root: $Root) ==="

# 1. Python available
$pythonExe = $null
if (Get-Command python -ErrorAction SilentlyContinue) { $pythonExe = "python" }
elseif (Get-Command python3 -ErrorAction SilentlyContinue) { $pythonExe = "python3" }
if (-not $pythonExe) {
  Write-Host "FAIL: Python not found. Install Python and ensure it is on PATH."
  exit 1
}
Write-Host "Using: $pythonExe ($(& $pythonExe --version 2>&1))"

# 2. Dependencies hint only
$null = & $pythonExe -c "import pytest" 2>&1
if ($LASTEXITCODE -ne 0) {
  Write-Host "Dependencies missing. Install with: pip install -r requirements.txt"
  Write-Host "Then activate your venv if you use one (e.g. .\.venv\Scripts\Activate.ps1) and re-run."
  exit 1
}

$Failed = @()
$Passed = @()

function Run-Stage {
  param([string]$Name, [string[]]$PytestArgs)
  Write-Host ""
  Write-Host "--- $Name ---"
  & $pythonExe -m pytest @PytestArgs -v --tb=short 2>&1 | Write-Host
  if ($LASTEXITCODE -eq 0) {
    $script:Passed += $Name
    return $true
  } else {
    $script:Failed += $Name
    return $false
  }
}

# 3. Core pytest suite
$null = Run-Stage "Core (identity, prekeys, x3dh, ratchet, envelope, replay, fork, sealed_sender)" @(
  "tests/test_identity.py", "tests/test_prekeys.py", "tests/test_x3dh.py",
  "tests/test_ratchet_basic.py", "tests/test_ratchet_out_of_order.py",
  "tests/test_protocol_envelope.py", "tests/test_replay_protection.py", "tests/test_fork_detection.py",
  "tests/test_sealed_sender.py"
)

# 4. Protocol integration
$null = Run-Stage "Protocol integration" @("tests/test_protocol_integration.py")

# 5. E2E session
$null = Run-Stage "E2E session" @(
  "tests/test_protocol_integration.py::test_protocol_integration_end_to_end",
  "tests/test_protocol_integration.py::test_end_to_end_via_relay_router"
)

# 6. Group messaging
$null = Run-Stage "Group messaging" @(
  "tests/test_group_state.py", "tests/test_group_membership.py", "tests/test_group_message_flow.py",
  "tests/test_group_mls.py", "tests/test_group_epoch.py"
)

# 7. Network hardening
$null = Run-Stage "Network hardening" @(
  "tests/test_mix_delay.py", "tests/test_cover_traffic.py", "tests/test_dummy_packets.py",
  "tests/test_network_cover_and_dummy.py", "tests/test_network_mix_and_timing.py", "tests/test_timing_defense.py"
)

# Summary
Write-Host ""
Write-Host "========== SUMMARY =========="
if ($Failed.Count -gt 0) {
  Write-Host "FAILED:"
  $Failed | ForEach-Object { Write-Host "  $_" }
  Write-Host "PASSED:"
  $Passed | ForEach-Object { Write-Host "  $_" }
  Write-Host "OVERALL: FAIL"
  exit 1
}
Write-Host "PASSED:"
$Passed | ForEach-Object { Write-Host "  $_" }
Write-Host "OVERALL: PASS"
exit 0
