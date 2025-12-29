docker exec -it ajh-website sh -c "export FLASK_APP=server.py && flask db migrate -m 'Added verification column' && flask db upgrade"
