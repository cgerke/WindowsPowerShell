function Get-WithHashTable {
    <#
      .SYNOPSIS
          Summary
      .DESCRIPTION
          Detail
      .EXAMPLE
          Get-WithHashTable
      .EXAMPLE
          Get-WithHashTable -JSON
      .EXAMPLE
          $(Get-WithHashTable).Property

      #>
      Param(
          [Parameter(Position = 0, mandatory = $false)]
          [switch] $JSON
      )

    $HashTable = @{
      "Node1" = @{
        Leaf = "Data1"
      }
      "Node2" = @{
        Leaf = "Data2"
        Leaf2 = "Data3"
        ExpandedLeaf = @{
          "ExLeaf3" = "Data4"
        }
      }
    }

    If($PSBoundParameters.ContainsKey("JSON")) {
      $OrderedHashtable = [ordered]@{}
      foreach ($Item in ($HashTable.GetEnumerator() | Sort-Object -Property Key)) {
          $OrderedHashtable[$Item.Key] = $Item.Value
      }
      $OrderedHashtable | ConvertTo-Json
    } Else {
      return $HashTable
    }

  }