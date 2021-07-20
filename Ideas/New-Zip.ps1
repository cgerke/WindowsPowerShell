$date = (Get-Date).ToString("yyyymmdd-hhmmss")
      $file = "C:\temp\myfile.txt"
      If (Test-Path -Path $file){
        "zip backup to $file.$date"
        try {
          Compress-Archive -LiteralPath "$file" -DestinationPath "$file.zip"
        } catch {
          $_.Exception.GetType().FullName
        }
      } Else {
        "Not here"
      }