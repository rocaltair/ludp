local ludp = require "ludp"

table.foreach(ludp, print)
table.foreach(ludp.Flags, print)

function server_run()
	local srv = assert(ludp.new_server())
	assert(srv:bind("localhost", 8899))
	while true do
		ludp.sleep(50)
		local msg, addr, port = srv:recvfrom()
		if msg then
			print("recv", msg, addr, port)
			srv:sendto("echo " .. msg, nil, addr, port)
		end
	end
end

server_run()
