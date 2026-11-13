FROM mongo:latest

# The official mongo image executes every file in /docker-entrypoint-initdb.d/
# on first boot (when the data directory is empty). A .js file is run with
# mongosh, so the seed script (already in mongosh syntax) loads the vulnerable
# app's data automatically -- no manual import step required.
ADD ./mongo.nosql /docker-entrypoint-initdb.d/mongo.js
