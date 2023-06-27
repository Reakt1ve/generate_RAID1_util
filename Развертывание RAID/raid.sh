#!/bin/bash

. ./UI.sh

disk_list="/dev/sda /dev/sdb /dev/sdc"
declare -A args_dict

let DISABLE_FORMAT_FLAG=0

function getopts() {
	local len_index=${#BASH_ARGV[@]}
	declare -a list_opt
	let list_opt_idx=0

	local size_index=""
	if [[ "$len_index" > "0" ]]; then
		size_index=$(expr $len_index - 1)
		for i in $(seq ${size_index} -1 0); do
			list_opt[$list_opt_idx]=${BASH_ARGV[$i]}
			(( list_opt_idx++ ))
		done

		printf '%s;' "${list_opt[@]}"
	else
		echo "empty"
	fi
}

function create_args_dict() {
	while (( "$#" )); do
		case $1 in
			-h | --help )
				args_dict["help"]="true"
			;;
			--disable-format )
				args_dict["disable_format"]="true"
			;;
			-s | --checksum )
				args_dict["checksum"]="true"
			;;
			-c | --create )
				args_dict["create"]="true"
			;;
			-d | --delete )
				args_dict["delete"]="true"
			;;
			* )
				print_help_screen
				exit 1
			;;
		esac
		shift 1
	done
}

function parse_args() {
	if [ ! -z ${args_dict["help"]} ]; then
		print_help_screen
		exit 1
	fi

	if [ ! -z ${args_dict["disable_format"]} ]; then
		DISABLE_FORMAT_FLAG=1
	fi

	if [ ! -z ${args_dict["create"]} ]; then
		if ! is_mdadm_installed; then
			print_mdadm_not_installed_screen
			exit 1
 		fi

 		if ! is_disks_exists "$disk_list"; then
 			print_disk_not_exists
 			exit 1
 		fi

 		if ! is_boot_mounted; then
			print_absent_boot_screen
			exit 1
		fi

		create_master_algorithm
		exit 1
	fi

	if [ ! -z ${args_dict["delete"]} ]; then
		if ! is_mdadm_installed; then
			print_mdadm_not_installed_screen
			exit 1
		fi

		if ! is_raid_exists; then
			print_raid_isnt_exists_screen
		else
			delete_master_algorithm
		fi

		exit 1
	fi

	if [ ! -z ${args_dict["checksum"]} ]; then
		if ! is_boot_partitions_exists "$disk_list"; then
			print_checksum_no_boot_screen
			exit 1
		fi

		check_boot_checksum "$disk_list"
		exit_code=$?
		if [ $exit_code -ne 0 ]; then
			print_wrong_boot_checksum_screen
		else
			echo "Boot разделы синхронизированы"
		fi

		exit 1
	fi
}

function check_script_persistence() {
	if [[ ! -f ./UI.sh ]]; then
		return 1
	fi

	return 0
}

function create_master_algorithm() {
	check_disks_state "$disk_list"
	exit_code=$?
	if [ $exit_code -eq 1 ]; then
		print_disk_in_raid_screen
		exit 1
	elif [ $exit_code -eq 2 ]; then
		print_disk_isnt_clear_screen
		exit 1
	fi

	create_partitions "$disk_list"
	create_mdadm
	copy_boot
	copy_os
	copy_var
	add_disks_to_raid
}

function check_disks_state() {
	local devices="$1"

	for device in $devices; do
		local device_file=$(echo "$device" | rev | cut -d '/' -f1 | rev)

		if is_disk_in_raid "$device_file"; then
			return 1
		fi

		if ! is_disk_clear "$device_file"; then
			return 2
		fi
	done

	return 0
}

MD_MAP=""
function scan_active_md() {
	local map_regex="(md[0-9]+)|(sd[a-z][1-9][0-9]*)"
	local md_map=$(cat /proc/mdstat | grep -Po "$map_regex" | xargs)
	MD_MAP="$md_map"
}

function delete_master_algorithm() {
	local md_regex="md[0-9]+"
	local partition_regex="sd[a-z][1-9][0-9]*"
        local disk_regex="sd[a-z]"

        scan_active_md

	local mdadm_disk=""
	local mdadm_disk_part_num=""

        OLD_IFS=$IFS
        IFS=$' '
        for md_map_elem in $MD_MAP; do
                if echo "$md_map_elem" | grep -P "$md_regex" >/dev/null; then
                        mdadm -S "/dev/${md_map_elem}" 2>/dev/null
                        exit_code=$?
                        if [ $exit_code -ne 0 ]; then
                                print_raid_in_use_screen
                                exit 1
                        fi

                        mdadm --remove "/dev/${md_map_elem}"
                elif echo "$md_map_elem" | grep -P "$partition_regex" >/dev/null; then
                        mdadm --zero-superblock "/dev/${md_map_elem}"
                        wipefs --all --force "/dev/${md_map_elem}"

			mdadm_disk=$(echo "$md_map_elem" | grep -Po "sd[a-z]")
			mdadm_disk_part_num=$(echo "$md_map_elem" | grep -Po "[1-9][0-9]*")
			parted -s "/dev/${mdadm_disk}" rm "$mdadm_disk_part_num"
                fi
        done
        IFS=$OLD_IFS
}

function check_boot_checksum() {
	local devices="$1"
	local folder_name1="/tmp/boot1"
	local folder_name2="/tmp/boot2"

        if [ -d ${folder_name1} ]; then
                local date_time=`echo $(($(date +%s%N)/1000000))`
                local folder_name1="${folder_name1}_${date_time}"
        fi

	if [ -d ${folder_name2} ]; then
                local date_time=`echo $(($(date +%s%N)/1000000))`
                local folder_name2="${folder_name2}_${date_time}"
        fi

	mkdir -p "${folder_name1}" "${folder_name2}"

	local first_device=$(echo "$devices" | cut -d ' ' -f1)
	mount $(echo "${first_device}1") "${folder_name1}"
	local prev_device_sum=$(find "$folder_name1" -type f -exec sha256sum {} + | awk '{print $1}' | sort | sha256sum)
	local folder_name1_was_first=1

	local error_found=0
	local current_folder=""
	for device in $(echo "$devices" | cut -d ' ' -f1 --complement); do
		if lsblk | grep "$folder_name1" >/dev/null; then
        		mount $(echo "${device}1") "${folder_name2}"
			local current_device_sum=$(find "$folder_name2" -type f -exec sha256sum {} + | awk '{print $1}' | sort | sha256sum)
		else
			mount $(echo "${device}1") "${folder_name1}"
			local current_device_sum=$(find "$folder_name1" -type f -exec sha256sum {} + | awk '{print $1}' | sort | sha256sum)
		fi

		if ! echo "$current_device_sum" | grep "$prev_device_sum" >/dev/null; then
			((error_found++))
			break
		fi

		prev_device_sum=$(echo "$current_device_sum")

		if [ $folder_name1_was_first -eq 1 ]; then
			umount "$folder_name1"
			folder_name1_was_first=0
		else
			umount "$folder_name2"
			folder_name1_was_first=1
		fi
	done

	umount "$folder_name1" 2>/dev/null
        umount "$folder_name2" 2>/dev/null
        rm -rf "$folder_name1" "$folder_name2"

	if [ $error_found -eq 1 ]; then
		return 1
	fi

	return 0
}

function is_user_root() {
	local current_user=$(whoami)

	if ! echo "$current_user" | grep "^root$" >/dev/null; then
		return 1
	fi

	return 0
}

function is_master_disk_active() {
	if lsblk | grep "/$" -A 1 -m 1 | grep -P "md[0-9]+" >/dev/null; then
		return 1
	fi

	return 0
}

function is_boot_mounted() {
	if lsblk | grep "/boot" >/dev/null; then
		return 0
	fi

	return 1
}

function is_boot_partitions_exists() {
	devices="$1"

	for device in $devices; do
		local device_boot_part=$(echo "${device}1" | grep -Po "sd[a-z]1")
		if ! lsblk | grep "$device_boot_part" >/dev/null; then
                	return 1
        	fi
	done

	return 0
}

function is_raid_exists() {
	if cat "/proc/mdstat" | grep -P "md[0-9]+" >/dev/null; then
		return 0
	fi

	return 1
}

function is_disks_exists() {
	local devices="$1"

	for device in $devices; do
		local device_file=$(echo "$device" | rev | cut -d '/' -f1 | rev)
		if ! lsblk | grep "$device_file" >/dev/null; then
			return 1
		fi
	done

	return 0
}

function is_disk_in_raid() {
	local disk="$1"

	if lsblk | grep "$disk" -A 1 | grep -P "md[0-9]+" >/dev/null; then
                return 0
        fi

	return 1
}

function is_disk_clear() {
	local disk="$1"

	if lsblk | grep "$disk" -A 1 | grep -P "${disk}1" >/dev/null; then
                return 1
        fi

        return 0
}

function is_mdadm_installed() {
	if apt list 2>/dev/null | grep mdadm | grep установлен >/dev/null; then
		return 0
	fi

	return 1
}

function create_partitions(){
	local devices="$1"

	OLD_IFS=$IFS
	IFS=$' '
	for i in $devices; do
		if [ $DISABLE_FORMAT_FLAG -eq 0 ]; then
			### Зануление дисков от сигнатур и прочего мусора
			echo "Очистка оставшихся данных на диске ${i}..."
			dd if=/dev/zero of="$i" bs=32M 2>/dev/null
			sync;sync;sync;sync
		fi

		parted -s "$i" mklabel msdos

		### 2 GB
		parted -s "$i" mkpart primary 1024Kib 2049Mib
		### 98 GB
		parted -s "$i" mkpart primary 2050Mib 102402Mib
		### остальной объем до 100%
		parted -s "$i" mkpart primary 102402Mib 100%
		sync;sync;sync;sync
	done
	IFS=$OLD_IFS
}

function create_mdadm(){
	mdadm --create /dev/md0 --metadata=1.0 --level=1 --raid-disk=2 /dev/sda2 /dev/sdb2
	mdadm --create /dev/md1 --metadata=1.0 --level=1 --raid-disk=2 /dev/sda3 /dev/sdb3

	mkfs.ext4 -F /dev/md0
	mkfs.ext4 -F /dev/md1
}

function copy_boot(){
	local folder_name="/tmp/mnt_raid"

	if [ -d ${folder_name} ]; then
		local date_time=`echo $(($(date +%s%N)/1000000))`
		local folder_name="${folder_name}_${date_time}"
	fi

	mkfs.ext2 -F /dev/sda1

	mkdir -p ${folder_name}
	mount /dev/sda1 ${folder_name}

	cp -dpRx /boot/* ${folder_name}

	local system_md_uuid=`blkid -o export /dev/md0 | grep "^UUID="`
	local root_from_fstab=`cat /etc/fstab | grep "[[:space:]]/[[:space:]]" | awk '{print $1}'`
	sed -i "s%${root_from_fstab}%${system_md_uuid}%g" ${folder_name}/boot.conf

	umount ${folder_name}
	rm -rf ${folder_name}

	dd if=/dev/sda1 of=/dev/sdb1 bs=16M status=progress
	dd if=/dev/sda1 of=/dev/sdc1 bs=16M status=progress
	sync;sync;sync;sync
}

function copy_os(){
	local folder_name="/tmp/mnt_raid"

	if [ -d ${folder_name} ]; then
		local date_time=`echo $(($(date +%s%N)/1000000))`
		local folder_name="${folder_name}_${date_time}"
	fi

	mkdir -p ${folder_name}
	mount /dev/md0 ${folder_name}

	cp -dpRx / ${folder_name}

	local boot_uuid=`blkid -o export /dev/sda1 | grep "^UUID="`
	local system_md_uuid=`blkid -o export /dev/md0 | grep "^UUID="`

	sed -i "/swap/d" ${folder_name}/etc/fstab

	local boot_from_fstab=`cat /etc/fstab | grep "[[:space:]]/boot[[:space:]]" | awk '{print $1}'`
	local root_from_fstab=`cat /etc/fstab | grep "[[:space:]]/[[:space:]]" | awk '{print $1}'`
	sed -i "s%${boot_from_fstab}%${boot_uuid}%g" ${folder_name}/etc/fstab
	sed -i "s%${root_from_fstab}%${system_md_uuid}%g" ${folder_name}/etc/fstab

	umount ${folder_name}
	rm -rf ${folder_name}
}

function copy_var(){
	local folder_name="/tmp/mnt_raid"
	local folder_name_var="/tmp/mnt_raid_var"

	if [ -d ${folder_name} ]; then
		local date_time=`echo $(($(date +%s%N)/1000000))`
		local folder_name="${folder_name}_${date_time}"
	fi

	if [ -d ${folder_name_var} ]; then
		local date_time=`echo $(($(date +%s%N)/1000000))`
		local folder_name_var="${folder_name_var}_${date_time}"
	fi

	mkdir -p ${folder_name}
	mkdir -p ${folder_name_var}

	mount /dev/md0 ${folder_name}
	mount /dev/md1 ${folder_name_var}

	cp -dpRx ${folder_name}/var/* ${folder_name_var}

	local var_md_uuid=`blkid -o export /dev/md1 | grep "^UUID="`
	echo "${var_md_uuid} /var	ext4	errors=remount-ro 0 1" >> "${folder_name}/etc/fstab"

	umount ${folder_name}
        umount ${folder_name_var}

	rm -rf ${folder_name} ${folder_name_var}
}

function add_disks_to_raid(){
	mdadm --add /dev/md0 /dev/sdc2
	mdadm --add /dev/md1 /dev/sdc3

	local folder_name="/tmp/mnt_raid"

	if [ -d ${folder_name} ]; then
		local date_time=`echo $(($(date +%s%N)/1000000))`
		local folder_name="${folder_name}_${date_time}"
	fi

	mkdir -p ${folder_name}
	mount /dev/md0 ${folder_name}
	mount /dev/sda1 /boot

	mdadm --detail --scan > ${folder_name}/etc/mdadm/mdadm.conf
	mdadm --detail --scan > /etc/mdadm/mdadm.conf
	update-initramfs -u -k all -t
	sync;sync;sync;sync

	umount ${folder_name}
	umount /boot
	rm -rf ${folder_name}

	dd if=/dev/sda1 of=/dev/sdb1 bs=16M status=progress
        dd if=/dev/sda1 of=/dev/sdc1 bs=16M status=progress
        sync;sync;sync;sync
}

if ! is_user_root; then
	print_no_root_permissions_screen
	exit 1
fi

if ! check_script_persistence; then
	echo "Нарушена целостность скрипта!"
	exit 1
fi

user_opts=$(getopts)
if [[ "$user_opts" == "empty" ]]; then
	print_help_screen
	exit 1
fi

if ! is_master_disk_active; then
	print_wrong_active_screen
	exit 1
fi

user_opts=$(echo "$user_opts" | tr ';' ' ' | xargs)
create_args_dict $user_opts
parse_args
