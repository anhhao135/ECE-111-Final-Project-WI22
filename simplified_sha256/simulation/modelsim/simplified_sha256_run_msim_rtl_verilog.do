transcript on
if {[file exists rtl_work]} {
	vdel -lib rtl_work -all
}
vlib rtl_work
vmap work rtl_work

vlog -sv -work work +incdir+C:/Repos/ECE-111-Final-Project-WI22/simplified_sha256 {C:/Repos/ECE-111-Final-Project-WI22/simplified_sha256/simplified_sha256.sv}

