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
	echo "  -f : Redefine config file to use (default $CFG_FILE)"
	echo
}

function info() {
	if [ -n "$DEBUG" -a "$DEBUG" -ne 0 ]; then
		TS=`date +%Y%m%dT%H%M%S`
		echo "$TS iface:$IFACE -- $@" >> $OUT
		echo "$TS iface:$IFACE -- $@" >&2
	fi
}

function warn() {
	# echo "WARN : $@" >&2
	info "WARN : $@"
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
			warn "cannot conf IRQ:$IRQ ($smp_file) CPUs:$_CPU_LIST"
		fi
		# grep -H . $smp_file
	done
}

info "Start set_irq_affinity"

## --- Parse command line arguments / parameters ---
while getopts "i:f:c:vh" option; do
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
		h|?|*)
			usage;
			warn "Unknown parameters!!!"
			exit 0
	esac
done
shift $(( $OPTIND - 1 ))

## --- Load config file ---
if [[ ! -e "$CFG_FILE" ]]; then
	info "ERROR : Cannot read config file: $CFG_FILE"
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

## --- The $IFACE variable must be resolved to continue ---
if [[ -z "$IFACE" ]]; then
	if [ -n "$1" ]; then
		IFACE=$1
		info "Setup NIC interface $IFACE (as arg1)"
	else
		usage
		echo "  Supports: To be called by the ifup scripts"
		echo "  - Then, expects environment variable \$IFACE is set"
		info "ERROR : Cannot resolve \$IFACE"
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

