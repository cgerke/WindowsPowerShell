function New-Compare {
    <#
    .SYNOPSIS
      Tree comparison.
    .DESCRIPTION
      Compare the contents of two paths.
    .EXAMPLE
      New-Compare -Path C:\temp -Alt C:\temp1
    #>
    Param(
      [Parameter(Position=0,mandatory=$true)]
      [string] $Path,$Alt
    )

      $Ref = Get-ChildItem -Recurse -path "$Path"
      $Diff = Get-ChildItem -Recurse -path "$Alt"
      Compare-Object -ReferenceObject $Ref -DifferenceObject $Diff | ForEach-Object {$_.InputObject.FullName}

    }