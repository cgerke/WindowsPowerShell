function Get-WithPipeline
{
    <#
  .SYNOPSIS
    Summary
  .DESCRIPTION
    Detail
  .EXAMPLE
    Get-WithPipeline -Object "object"
  .EXAMPLE
    "object","object2" | Get-WithPipeline
  #>
    Param(
        [Parameter(Position = 0, mandatory = $true, ValueFromPipeline = $true)]
        [string] $Object
    )

    process
    {
        foreach ( $i in $Object )
        {
            Write-Host $Object
        }
    }
}