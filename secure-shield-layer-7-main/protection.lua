local whitelist = {
    "127.0.0.1",
    "109.71.253.231",
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
    for i = 1, 8 do
        local index = math.random(1, #charset)
        token = token .. charset:sub(index, index)
    end
    return token
end

local function set_cookie()
    local token = generate_random_token()
    ngx.header['Set-Cookie'] = 'TOKEN=' .. token .. '; path=/; max-age=1800; HttpOnly'
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
    local current, err = limit_dict:get(key)

  
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
            local success, err, forcible = limit_dict:set(key, 1, 60)
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
<html>
<head>
    <title>Checking Your Browser...</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?compat=recaptcha" async defer></script>
    <style>
        html, body {
            height: 100%;
            margin: 0;
            padding: 0;
            background: url('https://cdn.discordapp.com/attachments/1260258995973652491/1263403213198196807/wp11957695-minecraft-2023-wallpapers.jpg?ex=669a1b6e&is=6698c9ee&hm=9e691ed9e831f3c8c1c819cc6487a767ee68a80da2ec8aa937c755d56d779e16&') no-repeat center center fixed;
            background-size: cover;
            color: #FFF;
            font-family: Arial, Helvetica, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            overflow: hidden; /* Hide overflow to prevent scrollbars */
        }
        .box {
            position: relative; /* Position for absolute particles */
            border: 5px solid #2e2f4d;
            background-color: rgba(34, 35, 57, 0.9); /* Adding transparency to see the background image */
            border-radius: 3px;
            text-align: center;
            padding: 70px 20px;
            max-width: 600px;
            width: 90%;
            z-index: 1; /* Ensure box is on top of particles */
        }
        @media (max-width: 600px) {
            .box {
                padding: 50px 10px;
                width: 100%;
            }
        }
        @media (max-width: 400px) {
            .box {
                padding: 30px 5px;
            }
        }
        .spinner {
            border: 8px solid rgba(255, 255, 255, 0.3);
            border-top: 8px solid #fff;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .loading-text {
            margin-top: 20px;
            font-size: 18px;
        }
        .discord-bubble {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background-color: #7289da;
            color: #fff;
            border-radius: 25px;
            text-decoration: none;
            font-size: 16px;
            transition: background-color 0.3s ease;
        }
        .discord-bubble:hover {
            background-color: #5a73c4;
        }

        /* Snowflake animation */
        .snowflake {
            position: absolute;
            top: -10px;
            background-color: #FFF;
            border-radius: 50%;
            opacity: 0.8;
            pointer-events: none; /* Ensure particles don't interfere with interactions */
            animation: snowfall linear infinite;
        }

        @keyframes snowfall {
            0% {
                transform: translateY(0) rotateZ(0deg) scale(1);
                opacity: 0.8;
            }
            100% {
                transform: translateY(100vh) rotateZ(360deg) scale(0.5);
                opacity: 0;
            }
        }
    </style>
    <script>
        function onSubmit(token) {
            document.cookie = "TOKEN=" + token + "; max-age=1800; path=/";
            window.location.reload();
        }

        // JavaScript to create and animate snowflakes
        document.addEventListener('DOMContentLoaded', function() {
            const container = document.body;
            const snowflakeCount = 50; // Adjust number of snowflakes as needed

            for (let i = 0; i < snowflakeCount; i++) {
                createSnowflake();
            }

            function createSnowflake() {
                const snowflake = document.createElement('div');
                snowflake.className = 'snowflake';
                snowflake.style.left = `${Math.random() * 100}vw`; // Random horizontal position
                snowflake.style.width = `${Math.random() * 5 + 2}px`; // Random size
                snowflake.style.height = snowflake.style.width;
                snowflake.style.animationDuration = `${Math.random() * 3 + 2}s`; // Random duration

                container.appendChild(snowflake);

                setTimeout(() => {
                    snowflake.remove(); // Remove snowflake after animation duration
                }, (Math.random() * 3 + 2) * 1000); // Match this to animation duration
            }

            setInterval(createSnowflake, 300); // Continuously create snowflakes
        });
    </script>
</head>
<body>
    <div class="box">
        <div class="spinner"></div>
        <div class="loading-text">Loading...</div>
        <h1>Checking Your Ip address...</h1>
        <p>Protected By FireHosting</p>
        <div class="g-recaptcha" data-sitekey="SITE-KEY" data-callback="onSubmit"></div>
        <a href="https://discord.gg/" class="discord-bubble">Join our Discord</a>
    </div>
</body>
</html>

        
                        
                <p id="client-ip" class="hidden">Your IP: ]] .. client_ip .. [[</p>
                <p class="unhide-link" id="toggle-link" onclick="toggleIPVisibility()">Click to unhide IP</p>
                <div class="g-recaptcha" data-sitekey="SITE-KEY" data-callback="onSubmit"></div>
            </div>
            <div class="footer">
                DDoS Protected<span></span>  by <span>FireHosting</span>
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

    if limit_dict:get("rate:" .. client_ip) >= 1000 then
        redirect_ip(client_ip)
        return
    end

    if ngx.var.cookie_TOKEN then
        local token = ngx.var.cookie_TOKEN
        if #token >= 5 then
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
