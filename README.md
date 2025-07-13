# IP IsHere Dev

![Screenshot](/assets/your-ip-screenshot.jpg)

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

You'll want to download the [run-app.sh](/run-app.sh) script in order to get the app running.

```log
[admin@ip ~]$ ./run-app.sh 
SELinux is active. Setting up SELinux contexts for ip application...
Cleaning up existing file contexts...
Setting file contexts...
Applying file contexts...
SELinux context setup complete!
Setting capabilities for ip binary...
Starting application...
Found ip.service. Starting via systemd...
Service ip.service started successfully
Service ip.service enabled for auto-start
Service status:
● ip.service - IP IsHere Service
     Loaded: loaded (/etc/systemd/system/ip.service; enabled; preset: disabled)
     Active: active (running) since Sat 2025-07-12 13:23:39 UTC; 226ms ago
   Main PID: 4856 (ip.ishere.dev-l)
      Tasks: 6 (limit: 4424)
     Memory: 2.9M
        CPU: 8ms
     CGroup: /system.slice/ip.service
             └─4856 /home/admin/ip.ishere.dev-linux-amd64

Jul 12 13:23:39 ip.ishere.dev systemd[1]: Started IP IsHere Service.
Jul 12 13:23:39 ip.ishere.dev ip.ishere.dev-linux-amd64[4856]: 2025/07/12 13:23:39 Starting HT…443
Jul 12 13:23:39 ip.ishere.dev ip.ishere.dev-linux-amd64[4856]: 2025/07/12 13:23:39 Starting HT…:80
Hint: Some lines were ellipsized, use -l to show in full.

```

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
