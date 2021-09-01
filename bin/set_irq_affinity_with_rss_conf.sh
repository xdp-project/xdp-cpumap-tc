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

function usage() {
	echo
	echo "Usage: $0 <iface> <cpu_list>"
	echo " - Script for binding NIC interface IRQs to specific CPUs"
	echo
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


if [[ -z "$IFACE" ]]; then
	if [ -n "$1" ]; then
		IFACE=$1
		info "Setup NIC interface $IFACE (as arg1)"
	else
		usage
		echo "Expected: To be called by the ifup scripts"
		echo "    And expect environment variable \$IFACE is set"
		exit 0
	fi
fi
info "Start set_irq_affinity"

if [[ ! -d /sys/class/net/$IFACE/ ]]; then
	warn "Invalid interface $IFACE"
	exit 0
fi

if [[ ! -d /sys/class/net/$IFACE/device ]]; then
	warn "Non-physical interface $IFACE - Skip IRQ adjustments"
	exit 0
fi

irq_list=$(get_iface_irqs $IFACE)

for IRQ in $irq_list ; do
	echo "IRQ: $IRQ"
	smp_file="/proc/irq/${IRQ}/smp_affinity_list"
	grep -H . $smp_file
done

# TODO: Have (positive) NIC list that need this adjustment

echo END
