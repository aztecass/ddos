#!/usr/bin/lua
--[[
  PhazaSoft DDoS antiflood
  Специально для пользователей SteelLinux
  http://steellinux.do.am
]]


-- ################## НАСТРОЙКА ################## >>>

local ports_protect={
	[{22}]=2,
	[{80,413}]=15,
	[{411,1209}]=3,
} -- защищаемые порты (группа задаётся через запятую) и разрешённое количество одновременных соединений для данной группы портов с одного IP

local ranges_allow={
	[{"0.0.0.0","0.0.0.0"}]="all", --local
	[{"10.0.0.0","10.255.255.255"}]="all",
	[{"127.0.0.0","127.255.255.255"}]="all",
	[{"172.16.0.0","172.31.255.255"}]="all",
	[{"192.168.0.0","192.168.255.255"}]="all",
} -- разрешённые диапазоны (white list) и порты для них через запятую (all означает все порты)

local time_ban=60*30 --время блокировки IP-адреса (в секундах)
local drop_allow=200 --разрешённое количество попыток соединения во время блокировки (при превышении блокировка продлевается)
local scan_period=10 --период между сканированиями (в секундах)
local log_folder="/var/log/ddos_block/" --папка для логов (в конце должен быть "/") (пустая строка "" означает отключение логов)
local filter_command="/bin/netstat -utan | egrep '^(tcp|udp)\\s+[0-9]+\\s+[0-9]+\\s+[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:(%PORTS)' " --шаблон команды для получения списка текущих соединений с защищаемыми портами (шаблон %PORTS заменится на защищаемые порты)
local ban_command="/usr/sbin/iptables -I INPUT -s %IP -j DROP " --шаблон команды блокировки IP-адреса
local unban_command="/usr/sbin/iptables -D INPUT -s %IP -j DROP " --шаблон команды удаления блокировки IP-адреса
local stat_command="/usr/sbin/iptables -L -n -v -x | grep 'DROP       all  \\-\\-  \\*      \\*' | grep -v 'all  \\-\\-  \\*      \\*       0.0.0.0/0' " --команда для получения статистики о заблокированных IP-адресах

-- ############################################## <<<
local VERSION="1.1"




local res,err=io.popen("whoami")
if res then
	local result=res:read("*a") or "" 
	res:close()
	if result:gsub("%s","")~="root" then
		print("ERR", "Run this program as root! Exiting.")
		return
	end
else
	print("ERR:popen:whoami", os.date(), tostring(err))
	return
end --нам нужны права рута

local function IPToLong(str)
	local d1,d2,d3,d4=str:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
	if not d1 or not d2 or not d3 or not d4 then return end
	d1=d1*1000000000
	d2=d2*1000000
	d3=d3*1000
	d4=d4+0
	if d1<=255000000000 and d2<=255000000 and d3<=255000 and d4<=255 then return d1+d2+d3+d4 end
end --преобразование строки айпи в число
local function LongToIP(num)
	local d1,_=math.modf(num/1000000000)
	num=num-(d1*1000000000)
	local d2,_=math.modf(num/1000000)
	num=num-(d2*1000000)
	local d3,_=math.modf(num/1000)
	local d4=num-(d3*1000)
	return d1.."."..d2.."."..d3.."."..d4
end --преобразование числа в строку айпи

local function FilterIPinRanges(tab)
	for ip in pairs(tab) do
		local lip=IPToLong(ip) or (print("ERR:IPToLong", os.date(), tostring(ip)))()
		for i in pairs(ranges_allow) do
			if lip>=i[1] and lip<=i[2] then
				if not next(ranges_allow[i]) then
					tab[ip]=nil
				else
					for p in pairs(tab[ip]) do
						if ranges_allow[i][p..""] then tab[ip][p]=nil end
					end
					if not next(tab[ip]) then tab[ip]=nil end
				end --разрешены все порты или некоторые?
				break
			end --ip в белом листе
		end
	end
	return tab
end --сброс статистики соединений с разешёнными портами для ip из белого листа

local ip_banned={} --заблокированные ip
local ip_stat={} --текущая статистика

res=""
for i in pairs(ports_protect) do
	for j=1,#i do res=res..i[j].." |" end
end --составляем команду фильтра защищаемых портов
res,_=res:gsub("|$","")
filter_command,_=filter_command:gsub("%%PORTS",res)

for i in pairs(ranges_allow) do
	res=ranges_allow[i]
	ranges_allow[i]={}
	for p in res:gmatch("(%d+)") do ranges_allow[i][p]=1 end
	i[1]=IPToLong(i[1])
	i[2]=IPToLong(i[2])
end --преобразование диапазонов ip в числа и портов в таблицы

if log_folder~="" then
	os.execute("mkdir -p "..log_folder.."banned")
	os.execute("mkdir -p "..log_folder.."unbanned")
end

print("Protected ports:")
res=""
for i in pairs(ports_protect) do
	for j=1,#i do res=res..i[j].."," end
	res,_=res:gsub(",$","")
	print("", res, "("..ports_protect[i].." conn. allow)")
	res=""
end
print("Ban time:", time_ban.." sec.")
print("Connection attempts count allowed while banned:", drop_allow)
print("Period between scans:", scan_period.." sec.")
print("Logs folder:", (log_folder=="" and "disabled" or log_folder))
print("START", os.date(), "v."..VERSION)

while true do

res,err=io.popen(stat_command)
if res then
	local result=res:read("*a") or ""
	res:close()
	local tab={}
	for c,ip in result:gmatch("(%d+)%s+%d+%s+DROP%s+all%s+%-%-%s+%*%s+%*%s+(%d+%.%d+%.%d+%.%d+)") do
		tab[ip]=c+0
	end
	for ip,c in pairs(tab) do
		if ip_banned[ip] then
			local c0,t,d=(ip_banned[ip]):match("^(%d+)%s+(%d+)%s+(.+)")
			if os.time()-t > time_ban then
				if (c+0<ip_stat[ip] and c+0<=drop_allow) or (c+0>=ip_stat[ip] and c-ip_stat[ip]<=drop_allow) then
					local s,_=unban_command:gsub("%%IP",ip)
					res,err=io.popen(s)
					if res then
						res:close()
						print("UNBAN", ip, c, os.date())
						if log_folder~="" then
							os.execute("mv -f "..log_folder.."banned/"..ip.." "..log_folder.."unbanned/ 2> /dev/null")
						end
						ip_banned[ip]=nil
						ip_stat[ip]=nil
					else
						print("ERR:popen:unban_command", os.date(), tostring(err))
					end --пробуем разблокировать
				else
					print("PROLONG", ip, c, os.date())
					if log_folder~="" then
						os.execute("echo '>>> "..os.date().."\t"..c.." (PROLONG)' >> "..log_folder.."banned/"..ip.." ; /bin/netstat -utanp | grep "..ip.." >> "..log_folder.."banned/"..ip)
					end
					ip_banned[ip]=c0.."\t"..os.time().."\t"..d
					ip_stat[ip]=c+0
				end --не превышает ли количество попыток соединения разрешённое число во время блокировки? Продлеваем бан или разблокируем?
			end --возможно, пришло время разблокировать?
		end --проверяем список блокировок на возможность разблокировки
	end --сканируем текущие соединения
	
	for ip in pairs(ip_banned) do
		if tab[ip]==nil then
			print("ZOMBIE", ip, "", os.date())
			if log_folder~="" then
				os.execute("mv -f "..log_folder.."banned/"..ip.." "..log_folder.."unbanned/ 2> /dev/null")
			end
			ip_banned[ip]=nil
			ip_stat[ip]=nil
		end
	end --удаление из базы банов-призраков
	tab=nil
else
	print("ERR:popen:stat_command", os.date(), tostring(err))
end --проверка статистики блокировок

res,err=io.popen(filter_command)
if res then
	local result=res:read("*a") or ""
	res:close()
	local tab={}
	for c,ip in result:gmatch("%w+%s+%d+%s+%d+%s+[%d%.]+:(%d+)%s+(%d+%.%d+%.%d+%.%d+)") do
		if not tab[ip] then tab[ip]={} end
		tab[ip][c]=(tab[ip][c] or 0)+1
	end --составление списка текущих соединений с сортировкой по портам
	tab=FilterIPinRanges(tab) --фильтруем белый список диапазонов ip
	for ip in pairs(tab) do
		for i in pairs(ports_protect) do
			local gres=0
			for j=1,#i do
				gres=gres+(tab[ip][i[j]..""] or 0)
			end
			if gres>ports_protect[i] then
				if ip_banned[ip]==nil then
					local s,_=ban_command:gsub("%%IP",ip)
					res,err=io.popen(s)
					if res then
						res:close()
						s,_=unban_command:gsub("%%IP",ip)
						print("BAN", ip, gres, os.date(), "(for unban: "..s..")")
						if log_folder~="" then
							os.execute("mv -f "..log_folder.."unbanned/"..ip.." "..log_folder.."banned/ 2> /dev/null ; echo '>>> "..os.date().."\t"..gres.."' >> "..log_folder.."banned/"..ip.." ; /bin/netstat -utanp | grep "..ip.." >> "..log_folder.."banned/"..ip)
						end
						ip_banned[ip]=gres.."\t"..os.time().."\t"..os.date()
						ip_stat[ip]=0
						--os.execute("sleep 1")
					else
						print("ERR:popen:ban_command", os.date(), tostring(err))
					end --пытаемся заблокировать
				else
					local c0,t,d=(ip_banned[ip]):match("^(%d+)%s+(%d+)%s+(.+)")
					ip_banned[ip]=(c0+0>gres) and (c0.."\t"..os.time().."\t"..d) or (gres.."\t"..os.time().."\t"..d) --просто обновляем данные об ip
				end --новый ip или уже заблокированный
				break
			end --блокируем ip, если превышен лимит одновременных соединений к группам защищаемых портов
		end
	end --вычисляем количетво соединений к защищаемым портам для всех ip
else
	print("ERR:popen:filter_command", os.date(), tostring(err))
end --проверяем текущие соединения

os.execute("sleep "..scan_period)
end
print("STOP", os.date())