#!/bin/bash
# -*- mode: shell-script; sh-shell: bash; sh-basic-offset: 8; sh-indentation:8; -*-
#
# Rewrite of script[1] 'set_irq_affinity' with extention for being called as
# Debian network if.up script (/etc/network/if-up.d/).
#
# [1] https://github.com/netoptimizer/network-testing/blob/master/bin/set_irq_affinity
#
# Old script was based on reading /proc/interrupts.  This approach is not
# possible on Mellanox NICs, because netdev interface name is not included.
#
# All Linux NICs (net_device's) have files under /sys/class/net/$IFACE and
# physical devices have a 'device' symlink: /sys/class/net/$IFACE/device
#
# For physical net_device's the directory /sys/class/net/$IFACE/device/msi_irqs/
# contains filename-numbers for each IRQ number.
# Then script knows which /proc/irq/${IRQ}/smp_affinity_list to adjust.

export OUT=/tmp/ifup-set-irq-affinity-DEBUG
DEBUG=$VERBOSITY
DEBUG=1 #Force debugging on

export CFG_FILE=/etc/smp_affinity_rss.conf

function usage() {
	echo
	echo "Script for binding NIC interface IRQs to specific CPUs"
	echo
	echo " Usage: $0 <iface>"
	echo "  -i : Cmdline set iface (default is env \$IFACE or shell arg1)"
	echo "  -c : Cmdline override CPU_LIST from config file"
	echo "  -n : Cmdline override RSS_INDIR_EQUAL_QUEUES from config file"
	echo "  -f : Redefine config file to use (default $CFG_FILE)"
	echo
}

export TIME_FMT="%Y%m%dT%H%M%S"

function info() {
	if [ -n "$DEBUG" -a "$DEBUG" -ne 0 ]; then
		TS=$(date +$TIME_FMT)
		echo "$TS iface:$IFACE -- $@" >> $OUT
		# echo "$TS iface:$IFACE -- $@" >&2
	fi
}

function warn() {
	TS=$(date +$TIME_FMT)
	echo "$TS iface:$IFACE -- WARN : $@" >> $OUT
	echo "$TS iface:$IFACE -- WARN : $@" >&2
}

function err() {
	TS=$(date +$TIME_FMT)
	echo "$TS iface:$IFACE -- ERROR : $@" >> $OUT
	echo "$TS iface:$IFACE -- ERROR : $@" >&2
	# Don't exit script, as it can cause ifup to not bringup interface
}


function get_iface_irqs()
{
	local _IFACE=$1

	if [[ ! -d /sys/class/net/$_IFACE/device ]]; then
		exit 0
	fi

	local msi_irqs=$(ls -x /sys/class/net/$_IFACE/device/msi_irqs)
	if [[ -z "msi_irqs" ]]; then
		exit 0
	fi

	# Walk IRQs for cleaning
	irqs=""
	for i in $msi_irqs ; do
		# Skip certain types of NIC IRQs
		if $(egrep -q -e "$i:.*(async|fdir)" /proc/interrupts) ; then
			# echo "SKIP : IRQ $i" >&2
			continue
		else
			: # echo "XXX msi $i ($irqs)" >&2
		fi
		irqs+="$i "
	done

	echo $irqs
}

function set_cpulist_iface()
{
	local _IFACE=$1
	local _CPU_LIST=$2
	irq_list=$(get_iface_irqs $_IFACE)

	for IRQ in $irq_list ; do
		info "NIC IRQ:$IRQ will be processed by CPUs: $_CPU_LIST"
		smp_file="/proc/irq/${IRQ}/smp_affinity_list"
		echo $_CPU_LIST > $smp_file
		local status=$?
		if [[ $status -ne 0 ]];then
			err "cannot conf IRQ:$IRQ ($smp_file) CPUs:$_CPU_LIST"
		fi
		# grep -H . $smp_file
	done
}

function set_rss_indir_queues()
{
	local _IFACE=$1
	local _QUEUES=$2

	if [[ -n "$_QUEUES" ]]; then
		info "Change RSS table to use first $_QUEUES queues"
		ethtool --set-rxfh-indir $IFACE equal $_QUEUES
		local status=$?
		if [[ $status -ne 0 ]];then
			err "cannot conf RSS indirection table with $_QUEUES"
		fi
	fi
}

function disable_vlan_offload()
{
	local _IFACE=$1

	if [[ -n "$DISABLE_VLAN_OFFLOAD_RX" ]]; then
		info "Disable hardware VLAN offload for RX"
		ethtool -K $_IFACE rxvlan off
		local status=$?
		if [[ $status -ne 0 ]];then
			err "cannot disable RX VLAN offload"
		fi
	fi
}

info "Start set_irq_affinity"

## --- Parse command line arguments / parameters ---
while getopts "i:f:c:n:vh" option; do
	case $option in
		i) # interface IFACE can also come from ifup env or arg1
			export IFACE=$OPTARG
			info "NIC Interface device set to: IFACE=$IFACE"
			;;
		f)
			export CFG_FILE=$OPTARG
			info "Redefine config file to: CFG_FILE=$CFG_FILE"
			;;
		c)
			export CPU_LIST2=$OPTARG
			info "Defining CPU_LIST via command line: CPU_LIST=$CPU_LIST2"
			;;
		n)
			export RSS_INDIR_EQUAL_QUEUES2=$OPTARG
			info "Defining RSS_INDIR_EQUAL_QUEUES via command line"
			;;

		h|?|*)
			usage;
			warn "Unknown parameters!!!"
			exit 0
	esac
done
shift $(( $OPTIND - 1 ))

## --- Load config file ---
if [[ ! -e "$CFG_FILE" ]]; then
	err "Cannot read config file: $CFG_FILE"
	#
	# Allow to continue of CPU_LIST were defined on cmdline
	if [[ -z "$CPU_LIST2" ]]; then
		exit 0
	fi
else
	source $CFG_FILE
fi

# Let cmdline CPU_LIST dominate over config file
if [[ -n "$CPU_LIST2" ]]; then
	export THE_CPU_LIST=$CPU_LIST2
else
	export THE_CPU_LIST=$CPU_LIST
fi

if [[ -n "$RSS_INDIR_EQUAL_QUEUES2" ]]; then
	export RSS_INDIR_EQUAL_QUEUES=$RSS_INDIR_EQUAL_QUEUES2
fi

## --- The $IFACE variable must be resolved to continue ---
if [[ -z "$IFACE" ]]; then
	if [ -n "$1" ]; then
		IFACE=$1
		info "Setup NIC interface $IFACE (as arg1)"
	else
		usage
		echo "  Supports: To be called by the ifup scripts"
		echo "  - Then, expects environment variable \$IFACE is set"
		err "Cannot resolve \$IFACE"
		exit 0
	fi
fi

if [[ ! -d /sys/class/net/$IFACE/ ]]; then
	warn "Invalid interface $IFACE"
	exit 0
fi

if [[ ! -d /sys/class/net/$IFACE/device ]]; then
	warn "Non-physical interface $IFACE - Skip IRQ adjustments"
	exit 0
fi

# --- Do IRQ smp_affinity adjustments ---
set_cpulist_iface $IFACE $THE_CPU_LIST

# --- Reduce/Setup RSS : RX flow hash indirection table ---
set_rss_indir_queues $IFACE $RSS_INDIR_EQUAL_QUEUES

# --- XDP cannot handle hardware offloaded VLAN info ---
disable_vlan_offload $IFACE

exit 0
