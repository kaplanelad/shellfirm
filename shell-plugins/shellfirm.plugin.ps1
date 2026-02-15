# Protect yourself from yourself!
# shellfirm will intercept any risky patterns and prompt you a small challenge for double verification.
# This hook triggers before every command execution and passes it to `shellfirm` for pattern checking.
# Read more: https://github.com/kaplanelad/shellfirm#how-it-works

# Add the following to your PowerShell profile (run: `notepad $PROFILE` to edit):

# Checks if shellfirm binary is accessible
if (Get-Command shellfirm -ErrorAction SilentlyContinue) {
    Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
        $line = $null
        $cursor = $null
        [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

        if ([string]::IsNullOrWhiteSpace($line)) {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
            return
        }

        if ($line -match 'shellfirm pre-command') {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
            return
        }

        shellfirm pre-command -c $line 2>$null
        if ($LASTEXITCODE -eq 0) {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        } else {
            [Microsoft.PowerShell.PSConsoleReadLine]::InvokePrompt()
        }
    }
} else {
    Write-Warning "`shellfirm` binary is missing. See installation guide: https://github.com/kaplanelad/shellfirm#installation."
}
