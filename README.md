# Friend Calendar App

Fun little side project to refresh knowledge on Go and maybe make organizing events easier.

# Setup
Ensure Templ & sqlc is installed

`go install github.com/a-h/templ/cmd/templ@latest &&  sudo snap install sqlc`

```bash
cat << EOF > .env
export GOOGLE_CLIENT_ID=<GOOGLE_CLIENT_ID>
export GOOGLE_CLIENT_SECRET=<GOOGLE_CLIENT_SECRET>
export POSTGRES_USERNAME=<POSTGRES_USERNAME>
export POSTGRES_PASSWORD=<POSTGRES_PASSWORD>
export DATABASE_URL=<POSTGRES_URL>
export ENCRYPTION_KEY=$(openssl rand -base64 32)
EOF
```

# Run

`./run.sh`

