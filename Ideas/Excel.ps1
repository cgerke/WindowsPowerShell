#Get list of files
$Directory = "C:\temp"
$File = "Test.xlsx"
$excel = new-object -com Excel.Application -Property @{Visible = $true}
$workbook = $excel.Workbooks.Open("$Directory\$File") # Open the file
$Log = ""

foreach ($sheet in $workbook.Worksheets) {
    # Verbose logging
    $LogSheetName = $sheet.Name()

    # Column manipulation
    $sheet.Cells.Item(1,1) = "ColumnName1"
    $sheet.Cells.Item(1,2) = "ColumnName2"
    $sheet.Cells.Item(1,3) = "ColumnName3"
    $sheet.Cells.Item(1,4) = "ColumnName4"
    $sheet.Cells.Item(1,5) = "ColumnName5"
    $sheet.Cells.Item(1,6) = "ColumnName6"

    # Data manipulation
    for ($i = $sheet.usedrange.rows.count; $i -gt 0; $i--)
    {
        "Scanning Loop $i"
        $action = "Rename"
        $IndicatorTypeCell = $sheet.Range("B$i").Text

        # Search and replace
        switch -CaseSensitive ( $IndicatorTypeCell )
        {
            "Domain" { $Log + "DomainName"; $sheet.Cells.Item($i, 2) = "DomainName" }
            "IP Address" { $Log + "IpAddress"; $sheet.Cells.Item($i, 2) = "IpAddress" }
        }

        $Log = "Sheet : $LogSheetName | Row : $i | IndicatorDataType : $IndicatorTypeCell > $action "
    }

    # Manipulate column order
    $sheet.Range("B1").EntireColumn.Copy() | out-null
    $sheet.Columns("A:A").Insert()
    $sheet.Paste($sheet.Range("A1"))
    $sheet.Range("C1").EntireColumn.Delete()

    # Export to CSV
    $LogSheetName = $sheet.Name()
    $FileSheetName = New-TemporaryFile
    $sheet.SaveAs("$FileSheetName.csv", 6)
    Copy-Item -Path "$FileSheetName.csv" -Destination "$Directory\$LogSheetName.csv"
}
#$workbook.Close($true) # Close workbook and save changes
#$excel.quit() # Quit Excel