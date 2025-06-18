#!/bin/bash
# Load the MITRE ATT&CK Enterprise knowledge base into a TypeDB database
# Pre-requisites: the TypeDB server has been started with the ./init-satrap.sh script

DB="satrap-skb-alpha"
TEMP_IMPORT_FILES="/opt/typedb-all-linux-x86_64/tmp_satrap"
DATA="enterprise.typedb"
SCHEMA="exp_schema.tql"

docker exec typedb \
	./typedb console --command="database delete $DB"

# Copy the dump files into a temp folder in the container
docker exec typedb mkdir $TEMP_IMPORT_FILES
docker cp $DATA typedb:$TEMP_IMPORT_FILES/$DATA
docker cp $SCHEMA typedb:$TEMP_IMPORT_FILES/$SCHEMA

# Import the DB
docker exec typedb \
	./typedb server import \
		--database=$DB \
		--port=1729 \
		--data=$TEMP_IMPORT_FILES/$DATA \
		--schema=$TEMP_IMPORT_FILES/$SCHEMA

# Remove the temp folder
docker exec typedb rm -rf $TEMP_IMPORT_FILES