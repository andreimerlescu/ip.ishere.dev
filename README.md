# IP IsHere Dev

This is an IP locator tool that allows you to ask for your own IP address, but the data 
collected on you is owned by you. You're welcome, from the future. This utility is an
invaluable asset to have in your toolbox. It's a super small app that allows you host
your own `ip.<your-domain.com>` that responds to `/` for TEXT response. To get a formatted
output, you'd use `/read.json` for JSON, `/read.ini` for INI, and `/read.yaml` for a 
downloaded YAML file. It'll contain two parameters, one `ipv4` and `ipv6` depending on
how you connect to the host.

## Installation

### Using Go

```bash
go install github.com/andreimerlescu/ip.ishere.dev
```

### Using Git

```bash
git clone git@github.com:andreimerlescu/ip.ishere.dev.git
cd ip.ishere.dev
make all
stat bin/ip.ishere.dev-linux-amd64
```

### Using Binary

```bash
curl -sL https://github.com/andreimerlescu/ip.ishere.dev/releases/download/v1.0.0/ip.ishere.dev-linux-amd64 --ouput ip.ishere.dev-linux-amd64 
stat ip.ishere.dev-linux-amd64
```

### Installation Next Steps (Required for Both Using Options Above)

You'll want to download the [run-app.sh](/run-app.sh) script in order to get the app.

The [ip.service](/ip.service) file should be installed inside of the `/etc/systemd/system`.

Then you should be able to start it with: 

```bash
sudo systemctl daemon-reload
sudo systemctl start ip.service
```

If you want to run it as a background service, you can run: 

```bash
sudo systemctl daemon-reload
sudo systemctl enable ip.service
```

This anticipates a `/home/admin/app/config.yaml` that points to something like: 

```yaml
domain: ip.ishere.dev
http: 80
https: 443
key: key.pem
cert: cert.pem
database: /home/admin/app-data/ip_requests.db
connections: 369
advanced: true
```

Then once you have the service running, you can access it with `curl` or your browser.

- [My IP Address](https://ip.ishere.dev)
- [JSON My IP Address](https://ip.ishere.dev/read.json)
- [YAML My IP Address](https://ip.ishere.dev/read.yaml)
- [INI My IP Address](https://ip.ishere.dev/read.ini)

```bash
curl -s -L https://ip.ishere.dev                             
IPv4: 17.17.17.17
IPv6: 

curl -sL https://ip.ishere.dev | grep IPv4 | awk '{print $2}'
17.17.17.17

curl -s -L https://ip.ishere.dev/read.json | jq -r '.ipv4'
17.17.17.17

```
