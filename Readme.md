Instalaltor projektu systemu jest plikiem install.sh
System zakłada istnieje bazy danych postgres gdzie dostępy należy zastąpić domyślnymi lub zostawić domyślne 
i tak skonfiugurować bazę danych jak w pliku conf/ipac.conf
Dodatkowo na bazie danych należy uruchomić skrypt, 
który stworzy tabele w bazię danych conf/postgres-db.sql

W celu zmiany reguł na jakiś działa śledzenie ruchu należy zmienić reguły w pliku conf/rules.conf
Przykłądowy wpis wygląda:
ForumStosowana|ipac~o|+|all||178.63.136.164||
ForumStosowana|ipac~fi|+|all||178.63.136.164||
ForumStosowana|ipac~i|+|all||178.63.136.164||
ForumStosowana|ipac~fo|+|all||178.63.136.164||

Aby skonfigurawać grafanę należy wczytać plik conf/grafana.json gdie skonfigurowany jest 
dashboard oraz podać namiary na bazę danych danych
