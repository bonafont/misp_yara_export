# misp_yara_export
Export MISP file signatures into yara files

Usage :

```Command : yara_export.py [-h : show help] [-json : add a json dump along with yara dump] <yara output filename>```

Example :

Export only to yara :
```python yara_export.py dump.yara ``` 
This command will dump all the MD5 SHA1 SHA256 signatures from the MISP database to a yara dump.

Export to yara along with a json dump
``` python yara_export.py -json dump.yara ``` 
This command is the same as the one above + export to a json file format


