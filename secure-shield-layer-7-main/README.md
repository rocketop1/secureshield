# SecureShield Layer 7 DDoS Protection

SecureShield Layer 7 DDoS Protection is a robust solution designed to protect your server from Layer 7 (application layer) DDoS attacks. This tool leverages Nginx for filtering and protecting your web applications.

## Features

- Protects against Layer 7 DDoS attacks
- Whitelisting IPs for trusted access
- Easy installation and configuration
- Lightweight and efficient

## Installation

Follow the steps below to install SecureShield Layer 7 DDoS Protection on your server:

### Step 1: Install the service

```bash
bash <(curl https://raw.githubusercontent.com/LylaNodes/SecureShield/main/secure-shield-installer.sh)
```
And, choose SecureShield Layer 7 Script(Number 1).

#### What to do? 

>
> Once, its finished installing everything navigate to the folder, /etc/nginx/conf.d/secure-shield-layer-7

```bash
cd /etc/nginx/conf.d/secure-shield-layer-7
```


#### Edit

Now, use nano protection.lua and edit it to your likings. **DO NOT REMOVE CREDITS**

Right under 

```lua 
local whitelist = {
    "127.0.0.1",
    "109.71.253.231",
}
```

White list, your IP's. For your services to bypass the captcha, for **EXAMPLE**

```lua 
local whitelist = {
    "127.0.0.1",
    "109.71.253.231",
    "143.195.189.130", // TEST IP RIGHT HERE, its fake.
}
```


#### How to configure? 
You, can edit the files in  ``nginx.conf`` or ``/etc/nginx/sites-available/test.conf``:


```lua
lua_shared_dict secure_shield_limit_dict 10m;
server {


location / {
access_by_lua_file /etc/nginx/conf.d/secure-shield-layer-7/protection.lua;
```
