local ludp = require "ludp"

function client_run()
	local cli = assert(ludp.new_client())
	while true do
		ludp.sleep(2000)
		cli:sendto("hello world", nil, "localhost", 8899)
		print(cli:recvfrom())
	end
end

client_run()
