# Misp yara export
Export MISP file signatures into a yara file

## Dependencies

The usage of poetry for this program is highly encouraged in order to resolve any dependency errors.

The command ``` poetry install``` will install all the necessary dependencies.

The command ``` poetry shell``` will spawn a shell with all the dependencies loaded.

## Usage :

```Command : yara_export.py [-h : show help] [-json : add a json dump along with yara dump] <yara output filename>```

The file keys.py should contain all the necessary information to connect to a MISP database

## Example :

Export only to yara :

```poet yara_export.py dump.yara ``` 

This command will dump all the MD5 SHA1 SHA256 signatures from the MISP database to a yara dump.

Export to yara along with a json dump :

``` python yara_export.py -json dump.yara ``` 

This command is the same as the one above + export to a json file format



