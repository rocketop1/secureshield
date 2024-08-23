local whitelist = {
    "127.0.0.1",
    "194.62.248.32",
}

local blacklist = {}

local function ip_in_list(ip, list)
    for _, value in ipairs(list) do
        if type(value) == "string" and value == ip then
            return true
        elseif type(value) == "table" and ngx.re.match(ip, value, "ijo") then
            return true
        end
    end
    return false
end

local function get_client_ip()
    local cf_ip = ngx.var.http_cf_connecting_ip
    if cf_ip then
        return cf_ip
    end

    local real_ip = ngx.var.http_x_forwarded_for
    if real_ip then
        local first_ip = real_ip:match("([^,%s]+)")
        if first_ip then
            return first_ip
        end
    end

    return ngx.var.remote_addr
end

local function generate_random_token()
    local charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local token = ""
    for i = 1, 16 do
        local index = math.random(1, #charset)
        token = token .. charset:sub(index, index)
    end
    return token
end

local function set_cookie()
    local token = generate_random_token()
    ngx.header['Set-Cookie'] = 'TOKEN=' .. token .. '; path=/; max-age=3600; HttpOnly'
end

local function delete_cookie()
    ngx.header['Set-Cookie'] = 'TOKEN=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly'
end

local adaptive_rate_limits = {}
local blocked_ips = {}
local redirect_duration = 30

local limit_dict = ngx.shared.secure_shield_limit_dict

local function rate_limit_ip(ip)
    if blocked_ips[ip] then
        return true
    end

    local key = "rate:" .. ip
    local current = limit_dict:get(key)

    if adaptive_rate_limits[ip] then
        if current and current >= adaptive_rate_limits[ip] then
            blocked_ips[ip] = true
            ngx.log(ngx.ERR, "IP " .. ip .. " blocked due to suspected DDoS attack")
            return true
        else
            limit_dict:incr(key, 1)
        end
    else
        if current then
            if current >= 1000 then
                adaptive_rate_limits[ip] = current + 500
                return true
            else
                limit_dict:incr(key, 1)
            end
        else
            local success, err = limit_dict:set(key, 1, 60)
            if not success then
                ngx.log(ngx.ERR, "Failed to set rate limit for key: " .. key .. ", error: " .. err)
            end
        end
    end
    return false
end

local function display_recaptcha(client_ip)
    ngx.log(ngx.ERR, "Displaying reCAPTCHA for IP: " .. client_ip)
    ngx.header.content_type = 'text/html'
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say([[
       <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WaveByte</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            height: 100vh;
            background: linear-gradient(to right, rgba(0, 0, 0, 0.8), rgba(0, 0, 0, 0.7)), 
                        url('https://image.api.playstation.com/vulcan/ap/rnd/202212/2018/GMXm533aVo9ZNp5l6ofFV6oD.jpg') no-repeat center center fixed;
            background-size: cover;
            justify-content: center;
            align-items: center;
            color: #e0e0e0;
        }
        .login-container {
            background-color: #1f1f1f;
            border-radius: 8px;
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.5);
            width: 100%;
            max-width: 360px;
            padding: 20px;
            text-align: center;
        }
        .login-container h1 {
            margin: 0;
            font-size: 24px;
            color: #ffffff;
        }
        .login-btn {
            display: inline-block;
            background-color: #7289da;
            color: #ffffff;
            text-decoration: none;
            padding: 12px 24px;
            border-radius: 4px;
            font-weight: bold;
            border: none;
            cursor: pointer;
            font-size: 16px;
            margin-top: 20px;
            text-transform: uppercase;
        }
        .login-btn:hover {
            background-color: #5b6eae;
        }
        .links {
            margin-top: 20px;
            font-size: 14px;
        }
        .links a {
            color: #1e90ff;
            text-decoration: none;
        }
        .links a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
  <h1>WaveByte Shield</h1>
                <p>Protected By WaveByte.xyz</p>
                <p id="client-ip" class="hidden">Your IP: ]] .. client_ip .. [[</p>
                <p class="unhide-link" id="toggle-link" onclick="toggleIPVisibility()">Click to unhide IP</p>
                <div class="g-recaptcha" data-sitekey="0x4AAAAAAAhdnNHweoJLlmPE" data-callback="onSubmit"></div>
            </div>
            <div class="footer">
                WaveByte Shield <span></span> - Made by <span>WaveByte</span>
            </div>
        </body>
        </html>
    ]])
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function display_blacklist_page(client_ip)
    ngx.log(ngx.ERR, "Displaying blacklist page for IP: " .. client_ip)
    ngx.header.content_type = 'text/html'
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say([[
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Denied</title>
            <style>
                html, body {
                    height: 100%;
                    margin: 0;
                    padding: 0;
                    background-color: #1b1c30;
                    color: #FFF;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                .box {
                    border: 5px solid #2e2f4d;
                    background-color: #222339;
                    border-radius: 3px;
                    text-align: center;
                    padding: 70px 0;
                    width: 100%;
                    height: 100%;
                    animation: fadeIn 1s ease-out, rotateIn 2s ease-in-out;
                }
                .footer {
                    position: absolute;
                    bottom: 10px;
                    width: 100%;
                    text-align: center;
                    color: #00f;
                    animation: slideInFromBottom 1s ease-out, glowEffect 2s ease-in-out infinite alternate;
                }
                .footer span {
                    color: #0f0;
                }
                
                @keyframes fadeIn {
                    0% {
                        opacity: 0;
                    }
                    100% {
                        opacity: 1;
                    }
                }
                
                @keyframes rotateIn {
                    0% {
                        transform: rotate(0deg);
                    }
                    100% {
                        transform: rotate(360deg);
                    }
                }
                
                @keyframes slideInFromBottom {
                    0% {
                        transform: translateY(100%);
                    }
                    100% {
                        transform: translateY(0);
                    }
                }
                
                @keyframes glowEffect {
                    0% {
                        text-shadow: 0 0 5px #00f;
                    }
                    100% {
                        text-shadow: 0 0 10px #0f0, 0 0 20px #00f;
                    }
                }
            </style>
        </head>
        <body>
            <div class="box">
                <h1>Access Denied</h1>
                <p>Your IP address has been blacklisted. Please contact the site administrator for assistance.</p>
            </div>
            <div class="footer">
                SecureShield<span></span> - Made by  <span>LylaNodes</span>
            </div>
        </body>
        </html>
    ]])
    delete_cookie()
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function redirect_ip(ip)
    ngx.log(ngx.ERR, "Redirecting IP " .. ip .. " to 109.71.253.231")
    ngx.header["Location"] = "http://109.71.253.231"
    ngx.status = ngx.HTTP_TEMPORARY_REDIRECT
    ngx.exit(ngx.HTTP_TEMPORARY_REDIRECT)
end

local function sanitize_input(input)
    return string.gsub(input, "[;%(')]", "")
end

local fun_facts = {
    "The Eiffel Tower can be 15 cm taller during the summer due to thermal expansion.",
    "Honey never spoils. Archaeologists have found pots of honey in ancient Egyptian tombs that are over 3,000 years old and still perfectly edible.",
    "The average person walks the equivalent of three times around the world in a lifetime.",
    "Octopuses have three hearts: two pump blood to the gills, and one pumps it to the rest of the body.",
    "Bananas are berries, but strawberries are not.",
    "The first oranges weren't orange. The original oranges from Southeast Asia were a tangerine-pomelo hybrid, and they were actually green.",
}

local function get_random_fun_fact()
    local index = math.random(1, #fun_facts)
    return fun_facts[index]
end

local function main()
    local client_ip = get_client_ip()
    local user_agent = ngx.var.http_user_agent or ""
    local request_method = ngx.var.request_method

    ngx.log(ngx.ERR, "Client IP: " .. tostring(client_ip))

    if ip_in_list(client_ip, whitelist) then
        ngx.log(ngx.ERR, "Client IP is whitelisted: " .. client_ip)
        set_cookie()
        return
    end

    if blocked_ips[client_ip] then
        ngx.log(ngx.ERR, "IP " .. client_ip .. " blocked due to suspected DDoS attack")
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say("Request blocked due to suspected DDoS attack")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    if rate_limit_ip(client_ip) then
        ngx.log(ngx.ERR, "Rate limit exceeded for IP: " .. client_ip)
        display_recaptcha(client_ip)
        return
    end

    local rate = limit_dict:get("rate:" .. client_ip)
    if rate and rate >= 1000 then
        ngx.log(ngx.ERR, "Rate limit threshold reached for IP: " .. client_ip)
        redirect_ip(client_ip)
        return
    end

    if ngx.var.cookie_TOKEN then
        local token = ngx.var.cookie_TOKEN
        if #token >= 16 then
            ngx.log(ngx.ERR, "Valid token cookie found")
            return
        else
            ngx.log(ngx.ERR, "Invalid token length, removing cookie")
            delete_cookie()
        end
    end

    ngx.log(ngx.ERR, "Client IP is not whitelisted, showing reCAPTCHA")
    display_recaptcha(client_ip)
end

main()
