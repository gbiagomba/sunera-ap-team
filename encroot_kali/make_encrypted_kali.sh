#!/bin/sh
###############################################################################
# This script is used to build an encrypted EBS-backed system for Amazon EC2. #
#                                                                             #
# Tested with ami-d0f89fb9 (64-bit EBS us-east-1 - Ubuntu 12.04.2 LTS)        #
# See https://help.ubuntu.com/community/UEC/Images for info on Ubuntu images. #
# Precise Pangolin: https://cloud-images.ubuntu.com/releases/precise/release/ #
#                                                                             #
###############################################################################
#                                                                             #
# Copyright (c) 2011, 2013 Henrik Gulbrandsen <henrik@gulbra.net>             #
#                                                                             #
# This software is provided 'as-is', without any express or implied warranty. #
# In no event will the authors be held liable for any damages arising from    #
# the use of this software.                                                   #
#                                                                             #
# Permission is granted to anyone to use this software for any purpose,       #
# including commercial applications, and to alter it and redistribute it      #
# freely, subject to the following restrictions:                              #
#                                                                             #
# 1. The origin of this software must not be misrepresented; you must not     #
#    claim that you wrote the original software. If you use this software     #
#    in a product, an acknowledgment in the product documentation would be    #
#    appreciated but is not required.                                         #
#                                                                             #
# 2. Altered source versions must be plainly marked as such, and must not be  #
#    misrepresented as being the original software.                           #
#                                                                             #
# 3. This notice may not be removed or altered from any source distribution,  #
#    except that more "Copyright (c)" lines may be added to already existing  #
#    "Copyright (c)" lines if you have modified the software and wish to make #
#    your changes available under the same license as the original software.  #
#                                                                             #
###############################################################################

exitValue=1
set -e

print_separator() {
    printf "%s" "----------------------------------------"
    echo "---------------------------------------"
}

### Parameters and validation #################################################

big_boot=false
trust_me=false
validate=false
if_count=1

while [ "_${1#-}" != "_$1" ]; do
    case $1 in
        --big-boot) big_boot=true; shift;;
        --trust-me) trust_me=true; shift;;
        --validate) validate=true; shift;;

        --if-count) if_count="$2"; shift 2;;
        --if-count=*) if_count="${1#--if-count=}"; shift;;

        *) break;;
    esac
done

if $validate; then
    dev=/dev/sdf
    host=www.example.org
    system=$3
else
    dev=$1
    host=$2
    system=$3
fi

if [ "${dev#/dev/}" = "${dev}" -o -z "$host" ]; then
    echo "Usage: ${0##*/} [<options>] <device> <domain> [<system>]"
    echo "    --big-boot: full system on /dev/sda1, not just /boot"
    echo "    --if-count: total number of ethX network interfaces"
    echo "    --trust-me: skip the confirmation for device erasing"
    echo "    --validate: run a few initial sanity checks and exit"
    echo "        device: the device where a blank EBS is attached"
    echo "        domain: DNS domain for decryption password entry"
    echo "        system: e.g. \"lucid-20101228\" or \"maverick/i386\""
    exit 1
fi

if ! [ "$if_count" -ge 1 -a "$if_count" -le 8 ] 2> /dev/null; then
    echo "The range is from --if-count=1 to --if-count=8"
    exit 1
fi

if [ "${host%.example.com}" != "${host}" -o -z "${host%example.com}" ]; then
    echo "No, dummy! You should use your own domain, not example.com!"
    exit 1
fi

if [ "${system#snap-}" != "$system" ]; then
    echo "Snapshot-based systems are still not supported."
    exit 1
fi

if [ "$(id -u)" != "0" ]; then
    echo "This script should be run as root."
    exit 1
fi

if [ ! -e /sbin/cryptsetup ]; then
    echo "Please install cryptsetup (using this command):"
    echo "    sudo apt-get -y install cryptsetup"; echo
    exit 1
fi

### Sanity checks #############################################################

cd $(dirname $0)

old=$([ "${system#snap-}" != "$system" ] && echo "true" || echo "false")
new=$( ($old || $big_boot) && echo "true" || echo "false")
ram=$($big_boot && echo "false" || echo "true")
big=$big_boot
ram_boot=$ram
home="$(pwd)"

if [ "$(which cryptsetup)" = "${home}/cryptsetup" ]; then
    echo "Bad PATH: ${home}/cryptsetup hides /sbin/cryptsetup"
    echo "Please update your PATH environment variable."
    exit 1
fi

need() {
    if ! $1; then return; fi

    if [ ! -e "${home}/$3" ]; then
        echo "Missing file: $3 - $4"
        exit 1
    else
        # Files moved via Windows may have lost permissions...
        chmod $2 $3
    fi
}

need true 600 "boot.key" "private SSL key for the boot partition"
need true 644 "boot.crt" "SSL certificate for the boot partition"
need $big 755 "init.sh" "boot script replacing /sbin/init"
need $big 644 "pre_init.sh" "boot script that gets the password"
need $ram 755 "cryptsetup" "initramfs hook script"
need $ram 755 "cryptsetup.sh" "initramfs cryptsetup replacement"
need true 755 "make_bozo_dir.sh" "bozohttpd home setup script"
need true 644 "index.html" "page that redirects to activate.cgi"
need true 755 "activate.cgi" "password-fetching CGI script"
need true 644 "hiding.gif" "animated GIF used to hide text"
need $new 644 "uecimage.gpg" "public key for Ubuntu images"

### Select a system version ###################################################

ARCH="unknown"

# Select a reasonable default architecture
file /bin/ls | grep -q 32-bit && ARCH="i386"
file /bin/ls | grep -q 64-bit && ARCH="amd64"

# Select a reasonable default system
RELEASE="precise"; EXT="20130411.1"
: "${system:=$RELEASE-$EXT/$ARCH}"

# Extract the architecture (everything after the last '/')
release="${system%/*}"; [ "$release" != "$system" ] && arch="${system##*/}";
arch="${arch:-$ARCH}"; system="$release"

# Extract the extension (everything after the first '-')
release="${system%%-*}"; [ "$release" != "$system" ] && ext="${system#*-}";

# Allow a simple "i386" or "amd64" requirement
if [ -z "$arch$ext" ]; then
  case $release in
    i386|amd64) arch="$release"; release="$RELEASE"; ext="$EXT";;
  esac
fi

# Require a valid architecture
if [ "$arch" != "i386" -a "$arch" != "amd64" ]; then
    echo "Invalid architecture: $arch"
    exit 1
fi

# The chroot would probably fail without this requirement
if [ "$ARCH" = "i386" -a "$arch" = "amd64" ]; then
    echo "Please build 64-bit systems on a 64-bit instance."
    exit 1
fi

# Workaround for a bad redirect in the default Maverick
if [ "$release" = "maverick" ] && [ -z "$ext" ]; then
    ext="20120410"
fi

### Confirm the version #######################################################

if $validate; then exit 0; fi
suffix=${ext:+-$ext}

# Guess the subdirectory
case "$ext" in
    alpha-*|beta-*) dir="$ext";;
    *) dir="release${suffix}";;
esac

# # Construct the page URL
page="https://cloud-images.ubuntu.com/releases/$release/$dir/"

# # Make a data directory
data="$home/data"
mkdir -p "$data"

# # Download the info page
if ! curl -Lfs "$page" > "${data}/release.html"; then
    echo "Invalid system: ${release}${suffix}"
    exit 1
fi

# # Extract the name of the release tarball
pattern='<a href="([^"]*-'$arch'\.tar\.gz)">\1</a>'
file=$(perl -ne "m[$pattern] && "'print "$1\n"' "$data/release.html")

# The image name is different in old tarballs
if echo "$file" | grep -q cloudimg; then
    image="$release-server-cloudimg-$arch.img"
    label="cloudimg-rootfs"
else
    image="$release-server-uec-$arch.img"
    label="uec-rootfs"
fi

# # Complain as early as possible
# if [ -z "$file" ]; then
#     echo "No tarball for system."
#     exit 1
# fi

### Final warning #############################################################

if [ ! -e "${dev}" ]; then
    echo "No device: ${dev}"
    exit 1
fi

if ! $trust_me; then
    echo "This script will erase ${dev}; are you sure (yes/no)?"

    while true; do
        read -p "Confirm: " erase
        if [ "_${erase}" = "_yes" -o "_${erase}" = "_no" ]; then
            break;
        fi
        echo "Please answer \"yes\" or \"no\"."
    done

    if [ "_${erase}" != "_yes" ]; then
        echo "Not erasing."
        exit 1
    fi

    echo
fi

### Password reading ##########################################################

read_password() {
    trap "stty echo; exit 0" INT 0

    while true; do
        stty -echo;
        read -p "Password for slot $1: " password1; echo > $(tty)
        read -p "Confirm the password: " password2; echo > $(tty)
        if [ "_${password1}" != "_${password2}" ]; then
            echo "Inconsistent; please try again." > $(tty)
            continue;
        fi

        printf ${password1}
        stty echo;
        break
    done
}

cat <<EOT
-------------------------------------------------------------------------------
Two secret passwords are needed for the encrypted filesystem. Random 128-bit
passwords can be generated by running this command on a local Unix system:

    openssl rand -hex 16

Paste them below, and write them like this on two small slips of paper:

    8ac5bc85    14e223f4    NOTE: Any of these keys will unlock the partition,
    834b2100    68ffdc68          so you would typically keep one for yourself
    2784cc06    e80ae348          and store the other in a safe place, just in
    caac18e9    ebe28786          case your wallet is stolen; or give each key
    -Slot-0-    -Slot-1-          to a single group member - revoke if needed.

Treat these notes like your home keys. That's probably better than trying to
memorize weak passwords. If your secrets are REALLY important, you can still
burn your sheet of paper and they won't get anything out of torturing you...

-------------------------------------------------------------------------------
EOT

# Get two passwords from the user
password0=$(read_password 0);
password1=$(read_password 1);

### Progress Bar ##############################################################

pbBarLength=74

pbCount=$pbBarLength
pbCountString="";
pbOtherString="";
set -o noglob

while [ $pbCount -gt 0 ]; do
    pbCountString="${pbCountString}#";
    pbOtherString="${pbOtherString}-";
    pbCount=$((pbCount-1));
done

show_progress() {
    local index total count other
    index=$1; total=$2

    if [ $index -gt $total ]; then
        index=$total
    fi

    count=$((pbBarLength*index/total))
    other=$((pbBarLength-count))

    printf "\r"
    printf "%s" $(echo $pbCountString | cut -b 1-$count 2> /dev/null)
    printf "%s" $(echo $pbOtherString | cut -b 1-$other 2> /dev/null)
    printf " %3d%%" $((100*index/total))
}

### Slow Jobs #################################################################

slowPid=""

kill_slow_job() {
    if [ -n "$slowPid" ]; then
        kill $slowPid 2> /dev/null || true;
        slowPid="";
    fi

    echo;
}

get_slow_index() { echo "0"; }
get_slow_total() { echo "100"; }
is_slow_reject() { [ $1 -lt $2 ]; }

run_slow_job() {
    local message; message=$1; shift
    local delay; delay=$1; shift
    local total stop index

    total=$(get_slow_total)
    stop=false
    index=0

    echo $message
    "$@" & slowPid=$!

    while ! $stop; do
        index=$(get_slow_index)
        [ -t 1 ] && show_progress $index $total
        ps $slowPid > /dev/null 2>&1 && sleep $delay || stop=true
    done

    if is_slow_reject $index $total; then
        show_progress $index $total
        printf "\nFailed.\n"
        slowPid=""
        exit 1
    fi

    show_progress $total $total
    printf "\nOK.\n";
    slowPid=""
}

### Verification and cleanup ##################################################

check() {
    # Set the variables
    local options message program value
    options="--keyring=$home/uecimage.gpg"
    message="$1"; program="$2" sums="$3"

    # Print the message
    printf "$message"

    # Download the checksum files (ignore missing files)
    curl -Lfs "$page/$sums.gpg" > "$data/$sums.gpg"
    if ! curl -Lfs "$page/$sums" > "$data/$sums"; then
        echo "N/A"
        return
    fi

    # Verify the signature
    if ! gpgv $options "$data/$sums.gpg" "$data/$sums" 2> /dev/null; then
        echo "Evil."
        exit 1;
    fi

    # Verify the checksum
    if grep "$file" "$data/$sums" | (cd $data; $program --check --status); then
        echo "OK."
    else
        echo "Failed."
        exit 1;
    fi
}

cleanup() {
    kill_slow_job;
    print_separator;

    if [ "_${work#/tmp/tmp.}" = "_${work}" ]; then
        echo "Unexpected work directory; refusing to clean."
        exit 1
    fi

    printf "Cleaning up....... "
 #   umount -l "${work}/ubuntu" 2> /dev/null || true
    umount -l "${work}/boot" 2> /dev/null || true
    umount -l "${work}/root/dev/pts" 2> /dev/null || true
    umount -l "${work}/root/proc" 2> /dev/null || true
    umount -l "${work}/root/sys" 2> /dev/null || true
    umount -l "${work}/root/boot" 2> /dev/null || true
    umount -l "${work}/root" 2> /dev/null || true
    rm -rf "${work}"

    cryptsetup luksClose $name 2> /dev/null || true
    stty echo; echo "OK."; echo
    exit $exitValue
}

### Data fetching #############################################################

echo_size() {
    local size unit number;
    size="${1}0"

    # Express the size in higher multiples...
    for unit in bytes KiB MiB GiB TiB; do
        if [ $size -ge 10240 ]; then size=$((size/1024)); else break; fi
    done

    # Get the integer part
    number=${size%?};

    # Add a decimal for higher multiples
    if [ _$unit != _bytes ]; then
        number="$number.${size#$number}";
    elif [ "$number" = 1 ]; then
        unit=byte
    fi

    # Echo the result
    echo "$number $unit"
}

# # Download the tarball if necessary
# if [ ! -e "${data}/$file" ]; then
#     echo; print_separator
#     wget -P "${data}" "${page}${file}"
# fi

# # Verify the checksums
# echo; print_separator
# check "Checking SHA256... " sha256sum SHA256SUMS
# check "Checking SHA1..... " sha1sum SHA1SUMS
# check "Checking MD5...... " md5sum MD5SUMS

# # Get the unpacked image size
# printf "Checking size..... "
# total=$(tar tfzv "${data}/${file}" ${image} | head -1 | awk '{print $3}')
# echo_size $total;

### Image unpacking ###########################################################

# Create a work directory
echo; print_separator;
work="$(mktemp --directory)"
trap cleanup INT 0

# # Unpack the filesystem
# touch ${work}/${image}
# get_slow_index() { ls -la "${work}/${image}" | awk '{print $5}'; }
# get_slow_total() { echo $total; }
# run_slow_job "Unpacking image" 1 \
#     tar xfz "${data}/${file}" -C "${work}" ${image}

# # Mount the unpacked image
# mkdir "${work}/ubuntu"
# mount -o loop,ro "${work}/${image}" "${work}/ubuntu"

### Disk formatting ###########################################################

bootLabel="bootfs"

# Partition the volume
echo; print_separator
/sbin/sfdisk -uM $dev <<EOT
0 1024 83 *
;
EOT

# Give udevd some time to mknod ${dev}1
sleep 2

# Create an ordinary Ext3 filesystem in the first partition
echo; print_separator
echo "Creating ext3 filesystem on ${dev}1"
/sbin/mkfs -t ext3 -L "${bootLabel}" "${dev}1"

# Find a free luks device
echo; print_separator; printf "Formatting encrypted area.... "
num=1; while [ -e "/dev/mapper/luks${num}" ]; do num="$((num+1))"; done
name="luks${num}"

# Temporarily save the passwords; they will probably never reach the disk
mask=$(umask); umask 077
printf "$password0" > "${work}/pw0.txt"
printf "$password1" > "${work}/pw1.txt"
umask $mask

# Create an encrypted area in the second partition
cryptsetup luksFormat -q -i 5 --key-size=512 ${dev}2 "${work}/pw0.txt"; echo "OK."
cryptsetup luksAddKey -q --key-file="${work}/pw0.txt" ${dev}2 "${work}/pw1.txt"
cryptsetup luksOpen --key-file="${work}/pw0.txt" ${dev}2 $name

# Shred the passwords
shred --remove "${work}/pw0.txt"
shred --remove "${work}/pw1.txt"

# Check the type of our original filesystem
fsType=$(df -T "/kali" | tail -1 | awk '{print $2}')

# Create a similar filesystem
echo; print_separator; echo "Creating $fsType filesystem on ${dev}2"
mkfs -t $fsType "/dev/mapper/$name"

# Add a label to find the root during boot
if $big_boot; then
    /sbin/e2label "${dev}1" "${label}"
else
    /sbin/e2label "/dev/mapper/$name" "${label}"
    echo "/dev/mapper/$name"
    echo "${label}"
fi

### Encrypted filesystem ######################################################

print_size() {
    df -k "$1" | tail -1 | awk '{print $3}'
}

# Mount the encrypted filesystem
echo; print_separator
mkdir "${work}/root"
mount /dev/mapper/$name "${work}/root"

# Calculate a range for the progress bar
printf "Checking total system size... "
totalSize=$(du -sk "/kali" | awk '{print $1}')
startSize=$(du -sk "${work}/root" | awk '{print $1}')
totalDiff=$((totalSize - startSize))
echo_size $((1024*totalDiff)); echo

# The df size contains a lot of overhead
sizeOffset=$(print_size "${work}/root");

# Define functions for the progress bar
get_slow_total() { echo $totalDiff; }
get_slow_index() { echo $(($(print_size "${work}/root") - sizeOffset)); }
is_slow_reject() {
    # Skip directories, since their exact sizes are unpredictable
    (cd "/kali"; find . \! -type d -ls | awk '{print $11, $7}' ) \
        | sort > "${work}/ubuntu.ls"
    (cd "${work}/root"; find . \! -type d -ls | awk '{print $11, $7}' ) \
        | sort > "${work}/root.ls"
    ! diff "${work}/ubuntu.ls" "${work}/root.ls" > /dev/null;
}

# Install Ubuntu on the encrypted filesystem
run_slow_job "Copying lots of data to ${dev}2" 5 \
    rsync --archive --hard-links "/kali/" "${work}/root/" || true

### Boot support ##############################################################

echo; print_separator

# Select suitable boot/root devices
bootDevice="LABEL=$bootLabel"
rootDevice="UUID=$(cryptsetup luksUUID ${dev}2)"

if $big_boot; then

    # Use partition 1 as root
    umount "${work}/root";
    mount "${dev}1" "${work}/root"

    # The overhead is different for a smaller partition
    sizeOffset=$(print_size "${work}/root");

    # Install Ubuntu on it
    run_slow_job "Copying data for the boot partition" 5 \
        rsync --archive --hard-links "/kali/" "${work}/root/"
else

    # Prepare to boot from an initramfs
    printf "Preparing /boot (${dev}1)......... "

    # Move all /boot files to the boot partition
    mkdir "${work}/boot"; mount "${dev}1" "${work}/boot"
    rsync --archive "${work}/root/boot/" "${work}/boot"
    rm -rf "${work}/root/boot/"*

    # Put the boot partition where it belongs
    mount --move "${work}/boot" "${work}/root/boot"

    # Add /boot to the fstab file
    echo "$bootDevice /boot ext3" >> "${work}/root/etc/fstab"
    echo "OK."
fi

echo; print_separator

# Update the GRUB menu to use sda1 instead of sda
sed -i -e 's/(hd0)/(hd0,0)/' "${work}/root/boot/grub/menu.lst"
sed -i -e 's/\/dev\/xvda1/LABEL=cloudimg-rootfs/' "${work}/root/boot/grub/menu.lst"

if $big_boot; then

    # Copy the simple files into place
    bozo_target="${work}/root/"
    cp "${home}/boot.key" "${work}/root/etc/ssl/private/"
    cp "${home}/boot.crt" "${work}/root/etc/ssl/certs/"
    cp "${home}/init.sh" "${work}/root/sbin/init"
    chmod 755 "${work}/root/sbin/init"
    perl -i -p - "${work}/root/sbin/init" <<- EOT
	s[/dev/sda2][$rootDevice];
	EOT

    # Copy pre_init.sh into place
    mkdir -p "${work}/root/etc/ec2"
    cp "${home}/pre_init.sh" "${work}/root/etc/ec2/"
    perl -i -p - "${work}/root/etc/ec2/pre_init.sh" <<- EOT
	s[^(pi_priv=).*][\$1"/etc/ssl/private/boot.key"];
	s[^(pi_cert=).*][\$1"/etc/ssl/certs/boot.crt"];
	s[^(pi_host=).*][\$1"$host"];
	EOT
else

    # Create the ${bozo_target} directory
    bozo_target="${work}/root/etc/initramfs-tools/boot/"
    mkdir -p ${bozo_target}

    # Copy the simple files into place
    cp "${home}/boot.key" "${bozo_target}"
    cp "${home}/boot.crt" "${bozo_target}"

    # Copy the cryptsetup hook
    cp "${home}/cryptsetup" "${work}/root/etc/initramfs-tools/hooks/"
    perl -i -p - "${work}/root/etc/initramfs-tools/hooks/cryptsetup" <<- EOT
	s[/dev/sda2][$rootDevice];
	EOT

    # Copy cryptsetup.sh
    mkdir -p "${work}/root/etc/ec2"
    cp "${home}/cryptsetup.sh" "${work}/root/etc/initramfs-tools/boot/"
    perl -i -p - "${work}/root/etc/initramfs-tools/boot/cryptsetup.sh" <<- EOT
	s[^(cs_host=).*][\$1"$host"];
	EOT

fi

# Copy all bozohttpd-related files
cp "${home}/make_bozo_dir.sh" "${bozo_target}"
cp "${home}/index.html" "${bozo_target}"
cp "${home}/activate.cgi" "${bozo_target}"
cp "${home}/hiding.gif" "${bozo_target}"

# Add a Natty repository if necessary
if [ "_${image#lucid}" != "_${image}" ]; then
listFile="${work}/root/etc/apt/sources.list"
grep "lucid main" $listFile | sed 's/lucid/natty/g' >> $listFile
fi

# Adjust the APT cache limit to avoid running out of space
if [ "_${image#lucid}" != "_${image}" ]; then
cat > "${work}/root/etc/apt/apt.conf" <<EOT
APT::Cache-Limit "67108864";
EOT
fi

# Add /etc/apt/preferences to get a newer bozohttpd version
if [ "_${image#lucid}" != "_${image}" ]; then
cat > "${work}/root/etc/apt/preferences" <<EOT
Package: *
Pin: release a=lucid
Pin-Priority: 600

Package: bozohttpd
Pin: release a=natty
Pin-Priority: 1000

Package: libssl0.9.8
Pin: release a=natty
Pin-Priority: 1000

Package: *
Pin: release o=Ubuntu
Pin-Priority: -10
EOT
fi

# Grab initrd and kernel for the first boot entry
menuFile="${work}/root/boot/grub/menu.lst"
initrd=$(grep "initrd" "$menuFile" | head -1 | awk '{print $2}')
kernel=$(grep "kernel" "$menuFile" | head -1 | awk '{print $2}')

# These symlinks are sometimes incorrect
rm -f "${work}/root/initrd.img.old" || true
rm -f "${work}/root/vmlinuz.old" || true
rm -f "${work}/root/initrd.img" || true
rm -f "${work}/root/vmlinuz" || true

# Use the extracted initrd and kernel instead
ln -s "$initrd" "${work}/root/initrd.img"
ln -s "$kernel" "${work}/root/vmlinuz"

# Temporarily use a working /etc/resolv.conf
resolv="${work}/root/etc/resolv.conf"
mv "${resolv}" "${resolv}.old" 2>/dev/null || true
cp "/etc/resolv.conf" "${work}/root/etc/"

# Some versions of Ubuntu already have cryptsetup
if [ ! -e "${work}/root/sbin/cryptsetup" ]; then
    update_command="apt-get -y install cryptsetup"
else
    update_command="update-initramfs -u"
fi

# Prepare extra network interfaces for convenience
if [ "$if_count" -gt 1 ]; then
    interfaces="${work}/root/etc/network/interfaces"
    if_index=1

    printf "\n# Other network interfaces\n" >> "$interfaces"
    while [ "$if_index" -lt "$if_count" ]; do
        echo "auto eth${if_index}" >> "$interfaces"
        echo "iface eth${if_index} inet dhcp" >> "$interfaces"
        if_index=$((if_index+1))
    done
fi

# Prepare the initial filesystem
chroot "${work}/root" <<- EOT
	set -e
	mount -t devpts devpts /dev/pts/
	mount -t proc proc /proc/
	mount -t sysfs sysfs /sys/
	localedef -f UTF-8 -i en_US --no-archive en_US.utf8
	apt-get -y update

	# Install SSL certificates without updating initramfs
	mv /usr/sbin/update-initramfs /usr/sbin/update-initramfs.old
	touch /usr/sbin/update-initramfs
	chmod a+x /usr/sbin/update-initramfs
	apt-get -y install ssl-cert
	mv /usr/sbin/update-initramfs.old /usr/sbin/update-initramfs

	# Install bozohttpd without starting inetd
	apt-get -y install update-inetd
	mv /usr/sbin/update-inetd /usr/sbin/update-inetd.old
	touch /usr/sbin/update-inetd
	chmod a+x /usr/sbin/update-inetd
	apt-get -y install bozohttpd
	mv /usr/sbin/update-inetd.old /usr/sbin/update-inetd
	EOT

# Prepare things for the "Big Boot" option
$big_boot && chroot "${work}/root" <<- EOT
	adduser --system --group --no-create-home bozo
	/bin/sh make_bozo_dir.sh /var/bozo
	chown -R bozo:bozo /var/bozo
	rm make_bozo_dir.sh index.html activate.cgi hiding.gif
	chown root:ssl-cert /etc/ssl/private/boot.key
	chmod 640 /etc/ssl/private/boot.key
	EOT

# Prepare things for the initramfs variety
$ram_boot && chroot "${work}/root" <<- EOT
	chown root:ssl-cert /etc/initramfs-tools/boot/boot.key
	chmod 640 /etc/initramfs-tools/boot/boot.key
	ln -s /usr/sbin/bozohttpd /etc/initramfs-tools/boot/
	ln -s . /boot/boot
	EOT

# Trigger an initramfs update and clean up
chroot "${work}/root" <<- EOT
	${update_command}
	apt-get -y clean
	mv /etc/resolv.conf.old /etc/resolv.conf 2> /dev/null
	umount /dev/pts
	umount /proc
	umount /sys
	EOT

exitValue=0

###############################################################################
