package rules

import data.macros.spawned_process

ls_launched = input {
	spawned_process
	input.comm == "ls"
}