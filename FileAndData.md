
## CSV files
### Dealing with Encoding

Source from [MSXFAQ / PowerShell und CSV-Datei](http://www.msxfaq.de/code/powershell/pscsv.htm)

If your dealing with character that are not properly recognized and showing as "?" then you are  probably a victim of an encoding issue.
Default encoding for Import-Csv is Unicode and there is no parameter to change that, but luckily we can get around that by using Get-Content.

```powershell
# Just use Get-Content and specify the encoding to use
Get-Content <PathTofile> -Encoding String | Convertfrom-csv -Delimiter ","

# In my case i got an ANSI encoded, ";"-separated file
# I also had to replace the header to make it match when imported, so i skip the first line and the defined a custom header
Get-Content -Path <PathTofile> -Encoding String | Select -Skip 1 | ConvertFrom-Csv -Delimiter ";" -Header "initials","name","surname","title","department","departmentname"

```
