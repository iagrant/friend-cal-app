#!/bin/bash

. .env
sqlc generate
templ generate
go run .
