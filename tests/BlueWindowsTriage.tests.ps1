Describe 'BlueWindowsTriage.ps1' {
    It 'creates output directory and script_log.txt' {
        $tempDir = Join-Path $env:TEMP "BWTTest_$([guid]::NewGuid())"

        $scriptPath = Join-Path $PSScriptRoot '..' 'BlueWindowsTriage.ps1'
        $sanitized = Get-Content $scriptPath | Where-Object { $_ -notmatch '^\s*exit\s*$' }
        $tempScript = Join-Path $env:TEMP 'BWT_Temp.ps1'
        Set-Content -Path $tempScript -Value $sanitized -Force

        Mock -CommandName New-Item -MockWith { @{'FullName'=$Path} } -Verifiable
        Mock -CommandName Start-Transcript -MockWith { } -Verifiable
        Mock -CommandName Stop-Transcript { }
        Mock -CommandName Start-Job { }
        Mock -CommandName Wait-Job { }
        Mock -CommandName Remove-Job { }

        . $tempScript -outputDir $tempDir

        Assert-MockCalled New-Item -ParameterFilter { $ItemType -eq 'Directory' -and $Path -eq $tempDir } -Times 1
        Assert-MockCalled Start-Transcript -ParameterFilter { $Path -eq "$tempDir\script_log.txt" } -Times 1
    }
}
