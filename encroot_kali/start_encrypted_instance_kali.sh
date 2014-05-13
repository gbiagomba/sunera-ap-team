#!/bin/sh
###############################################################################
# This script is used to start an encrypted EBS-backed system for Amazon EC2. #
# It uses the EC2 API, and calls make_encrypted_ubuntu.sh to create a system. #
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

### Options ###################################################################

instanceName=$(date "+Linux_%F_%H.%M.%S")
volumeSize="8"
options=""
addressList=""
groupList=""
subnet=""
system=""
vpc=""

is_ip_address() {
    local address="$1"
    local x

    for x in $(echo $address | tr "." " "); do
        if ! [ "$x" -ge 0 -a "$x" -le 255 ] 2> /dev/null; then
            return 1
        fi
    done

    return 0
}

is_ip_network() {
    local network="${1%/*}"
    local netmask="${1##*/}"

    if ! is_ip_address "$network"; then
        return 1
    fi

    # This is the range currently supported for EC2...
    if ! [ "$netmask" -ge 16 -a "$netmask" -le 28 ] 2> /dev/null; then
        return 1;
    fi

    return 0
}

add_address() {
    local address="$1"

    if ! is_ip_address $address; then
        echo "Invalid IP address: \"$address\""
        exit 1
    fi

    addressList="${addressList:+$addressList }$address"
    groupList="$groupList;"
}

add_group() {
    local group="$1"

    if [ -n "$(echo $group | tr -d '[:alnum:] .-_]')" ]; then
        echo "Invalid group name: \"$group\""
        exit 1
    fi

    if [ -n "${groupList##*;}" ]; then
        groupList="${groupList},"
    fi

    groupList="${groupList}${group}"
}

set_subnet() {
    if [ -n "$subnet" ]; then
        echo "Only one --subnet option is allowed; use --address instead!"
        exit 1
    fi

    subnet="$1"
}

while [ "${1#-}" != "$1" ]; do
    case $1 in
        --big-boot) options="$options --big-boot"; shift;;
        --address) add_address "$2"; shift 2;;
        --address=*) add_address "${1#--address=}"; shift;;
        --group) add_group "$2"; shift 2;;
        --group=*) add_group "${1#--group=}"; shift;;
        --name) instanceName="$2"; shift 2;;
        --name=*) instanceName="${1#--name=}"; shift;;
        --size) volumeSize="$2"; shift 2;;
        --size=*) volumeSize="${1#--size=}"; shift;;
        --subnet) set_subnet "$2"; shift 2;;
        --subnet=*) set_subnet "${1#--subnet=}"; shift;;
        --system) system="$2"; shift 2;;
        --system=*) system="${1#--system=}"; shift;;
        --vpc) vpc="$2"; shift 2;;
        --vpc=*) vpc="${1#--vpc=}"; shift;;
        -*) echo "Invalid option: $1"; exit 1;;
        *) break;;
    esac
done

### Basic checks ##############################################################

SUDO="$(which sudo)"
domain=$1

if [ -z "$domain" ]; then
    echo "Usage: ${0##*/} [<options>] <domain>"
    echo " --address <a> : private IP address; use once per interface"
    echo " --big-boot    : full system on /dev/xvda1, not just /boot"
    echo " --group <g>   : security group; use once per required group"
    echo " --name <n>    : name of the instance; default is Linux_*"
    echo " --size <s>    : total volume size in GiB; /boot is 1 GiB"
    echo " --subnet <s>  : subnet ID for the started VPC instance"
    echo " --system <s>  : e.g. \"lucid-20101228\" or \"maverick/i386\""
    echo " --vpc <v>     : Virtual Private Cloud; disambiguates addresses"
    echo "   domain      : DNS domain for decryption password entry"
    exit 1
fi

if [ ! -e "$(dirname $0)/make_encrypted_kali.sh" ]; then
    echo "Missing file: make_encrypted_kali.sh - system creation script"
    exit 1
fi

# Things get really confusing if these conflict
if [ -n "$subnet" ] && [ -n "$addressList" ]; then
    echo "You can specify either subnet or addresses, but not both"
    exit 1
fi

# A VPC conflicting with an implicit subnet would also be weird
if [ -n "$vpc" ] && [ -z "$subnet" ] && [ -z "$addressList" ]; then
    echo "The --vpc option must be used with subnet or addresses"
    exit 1
fi

$SUDO "$(dirname $0)/make_encrypted_kali.sh" --validate 

### Initialization ############################################################

dots() { perl -e 'print $ARGV[0], "."x(40-length($ARGV[0])), "... "' "$*"; }
print_separator() {
    printf "%s" "----------------------------------------"
    echo "---------------------------------------"
}

# Prepare things for EC2 operations
export EC2_API_VERSION="2013-02-01"
ORIGINAL_AWSAPI_FILE_DIR="$AWSAPI_FILE_DIR"
METADATA=http://169.254.169.254/latest/meta-data
PATH="$(dirname $0):$PATH"

# Figure out which availability zone we're in and set the endpoint
zone=$(curl -s "$METADATA/placement/availability-zone")
export EC2_ENDPOINT="https://ec2.${zone%?}.amazonaws.com/"

# Describe the instance we're running on
workInstance=$(curl -s "$METADATA/instance-id")
$(awsapi ec2.DescribeInstances InstanceId.1=$workInstance \
    reservationSet.1.{ \
        instancesSet.1.{ \
            buildSubnet:subnetId or "", \
            group:groupSet.1.groupId, \
            key:keyName, type:instanceType, \
            arch:architecture \
        } \
    } \
)

# Use a 32-bit architecture if the user explicitly requires it
if [ "${system%/i386}" != "$system" ]; then
    arch="i386"
fi

# Select a kernel suitable for this architecture and region
case $arch in
    i386)
        case $zone in
            ap-northeast-1?) kernelId="aki-3e99283f";; # Tokyo
            ap-southeast-1?) kernelId="aki-f41354a6";; # Singapore
            ap-southeast-2?) kernelId="aki-3f990e05";; # Sydney
            eu-west-1?)      kernelId="aki-89655dfd";; # Ireland
            sa-east-1)       kernelId="aki-ce8f51d3";; # São Paulo
            us-east-1?)      kernelId="aki-b2aa75db";; # Northern Virginia
            us-gov-west-1)   kernelId="aki-77a4c054";; # AWS GovCloud (US)
            us-west-1?)      kernelId="aki-e97e26ac";; # Northern California
            us-west-2?)      kernelId="aki-f637bac6";; # Oregon
            *) echo "Unknown zone: $zone"; exit 1;
        esac;;
    x86_64)
        case $zone in
            ap-northeast-1?) kernelId="aki-40992841";; # Tokyo
            ap-southeast-1?) kernelId="aki-fa1354a8";; # Singapore
            ap-southeast-2?) kernelId="aki-3d990e07";; # Sydney
            eu-west-1?)      kernelId="aki-8b655dff";; # Ireland
            sa-east-1)       kernelId="aki-c88f51d5";; # São Paulo
            us-east-1?)      kernelId="aki-b4aa75dd";; # Northern Virginia
            us-gov-west-1)   kernelId="aki-75a4c056";; # AWS GovCloud (US)
            us-west-1?)      kernelId="aki-eb7e26ae";; # Northern California
            us-west-2?)      kernelId="aki-f837bac8";; # Oregon
            *) echo "Unknown zone: $zone"; exit 1;
        esac;;
    *) echo "Unknown arch: $arch"; exit 1;
esac

### Prepare subnets ###########################################################

vpc_filter=""
params=""

# Only use subnets that belong to the VPC
if [ -n "$vpc" ]; then
    vpc_filter="Filter.0.Name=vpc-id Filter.0.Value=$vpc"
fi

# Allow "--vpc ff068f90" instead of "--vpc vpc-ff068f90"
if echo $vpc | grep -E "^[[:xdigit:]]{8}$" > /dev/null; then
    vpc="vpc-$vpc"
fi

# Allow "--subnet c6169fa9" instead of "--subnet subnet-c6169fa9"
if echo $subnet | grep -E "^[[:xdigit:]]{8}$" > /dev/null; then
    subnet="subnet-$subnet"
fi

# Allow "--subnet 10.0.0.0/24" instead of "--subnet c6169fa9"
if is_ip_network "$subnet"; then

    # List all subnets that match the CIDR notation
    $(awsapi ec2.DescribeSubnets $vpc_filter \
        Filter.1.Name=cidr Filter.1.Value="$subnet" \
        subnetList:subnetSet.n.subnetId)

    # There can be only one
    for subnetId in $subnetList; do
        if [ "$subnetId" = "$subnetList" ]; then
            subnet="$subnetId"
        else
            echo "Ambiguous subnet $subnet; use the --vpc option!"
            exit 1
        fi
    done
fi

# Option 1: one or more addresses with implicit subnets
if [ -n "$addressList" ]; then

    # Get a list of all suitable subnets
    $(awsapi ec2.DescribeSubnets net+subnetSet.n.{ \
        $vpc_filter vpcId, subnetId, cidrBlock \
    })

# Option 2: a subnet with the address selected by AWS
else

    # Use the build subnet by default
    if [ -z "$subnet" ]; then
        subnet="$buildSubnet"
    fi

    # If we have a subnet now:
    if [ -n "$subnet" ]; then

        # Add the subnet and remember the VPC
        params="$params SubnetId=$subnet"
        $(awsapi ec2.DescribeSubnets SubnetId="$subnet" \
            subnetSet.1.vpcId)

        # Complain if the --vpc option conflicts with our subnet
        if [ -n "$vpc" ] && [ "$vpc" != "$vpcId" ]; then
            echo "Conflicting VPC; ${vpc#vpc-} != ${vpcId#vpc-}"
            exit 1
        else
            vpc="$vpcId"
        fi

    fi

fi

### Security Group Handling ###################################################

groupIndex=1

add_group_params() {
    local groupList="$1"
    local prefix="$2"
    local group groupId

    # Split the comma-separated $groupList into $@
    IFS=","; set -- $groupList; unset IFS;

    # For each group in the list:
    for group in "$@"; do

        # Allow "--group fc02f495" instead of "--group sg-fc02f495"
        if echo $group | grep -E "^[[:xdigit:]]{8}$" > /dev/null; then
            group="sg-$group"
        fi

        # If it doesn't look like an ID, interpret it as a name
        if ! echo $group | grep -E "^sg-[[:xdigit:]]{8}$" > /dev/null; then

            # Look up the group ID for that name (extra filter for non-vpc)
            $(awsapi ec2.DescribeSecurityGroups $vpc_filter \
                Filter.1.Name=group-name Filter.1.Value="$group" \
                sg+securityGroupInfo.n.{ groupId, vpcId eq "$vpc" })

            # Complain if it fails
            if [ -z "$sgList" ]; then
                printf "No group named \"$group\" exists for EC2-"
                if [ -n "$vpc" ]; then echo "VPC ${vpc#vpc-}"
                else echo "Classic"; fi
                exit 1
            fi

            # Use the ID if it works
            group="$(sg.groupId)"
        fi

        # Add this group ID to the list of parameters
        params="$params ${prefix}SecurityGroupId.$groupIndex=$group"
        groupIndex=$((groupIndex+1))

    done
}

### Prepare interfaces ########################################################

index=0

# Prints the first $count bits of $ipAddress as a binary string
print_ip_bits() {
    local ipAddress="$1" count="$2"
    perl -e 'print unpack "B'$count'", pack"C*", split/\./,"'$ipAddress'"'
}

# address_in_subnet "10.0.0.42" "10.0.0.0/24" should be true
address_in_subnet() {
    set "$1" $(echo "$2" | tr "/" " ")
    local address="$1" network="$2" count="$3"

    address=$(print_ip_bits $address $count)
    network=$(print_ip_bits $network $count)
    [ "$address" = "$network" ]
}

# Extract the instance groups
instanceGroups="${groupList%%;*}"
groupList="${groupList#*;}"

# EC2-Classic and EC2-VPC without explicit addresses
if [ -z "$addressList" ]; then
    add_group_params "$instanceGroups"
    if [ -n "$subnet" ]; then
        params="$params SubnetId=$subnet"
    fi
fi

# For each private IP address:
for address in $addressList; do
    subnet=""

    # Try to find a unique subnet that works
    for net in $netList; do
        if address_in_subnet "$address" "$(net.cidrBlock)"; then
            if [ -z "$subnet" ]; then
                subnet="$(net.subnetId)"
                vpcId="$(net.vpcId)"
            else
                echo "Ambiguous subnet for $address; use the --vpc option!"
                exit 1
            fi
        fi
    done

    # Abort if no subnet is good enough
    if [ -z "$subnet" ]; then
        echo "No existing subnet includes $address; please create one!"
        exit 1
    fi

    # Once we have a VPC, all subnets should belong to it
    if [ -z "$vpc" ]; then
        vpc="$vpcId"
    elif [ "$vpcId" != "$vpc" ]; then
        echo "The addresses belong to different VPCs"
        exit 1
    fi

    # Extract the interface groups
    interfaceGroups="${groupList%%;*}"
    groupList="${groupList#*;}"

    # Add groups and private IP addresses
    add_group_params "$instanceGroups" "NetworkInterface.$index."
    add_group_params "$interfaceGroups" "NetworkInterface.$index."
    params="$params NetworkInterface.$index.{ \
        DeviceIndex=$index, SubnetId=$subnet, \
        PrivateIpAddresses.1.{ \
            PrivateIpAddress=$address, \
            Primary=true \
        } \
    }"

    index=$((index+1))

done

# Remember to update /etc/network/interfaces
if [ "$index" -gt 1 ]; then
    options="$options --if-count=$index"
fi

### Domain Validation #########################################################

public=true

# Try to get an IP address for the domain
if ! is_ip_address "$domain"; then
    ipAddress=$(dig +short $domain | tail -1)
else
    ipAddress="$domain"
fi

# Complain if that fails
if [ -z "$ipAddress" ]; then
    echo "No IP address found for $domain"
    exit 1
fi

# See if it's our private address
for address in $addressList; do
    if [ "$address" = "$ipAddress" ]; then
        public=false; break
    fi
done

# For public addresses:
if $public; then

    # Get some information about the address
    $(awsapi ec2.DescribeAddresses \
        Filter.1.Name=public-ip Filter.1.Value.1="$ipAddress" \
        addressesSet.1.{ \
            addressType:domain or "", \
            allocationId or "" \
        } \
    )

    # Make error messages less redundant
    if [ "$domain" != "$ipAddress" ]; then
        addressText="for $domain ($ipAddress)"
    else
        addressText="($ipAddress)"
    fi

    if [ -z "$addressType" ]; then
        echo "Invalid IP address $addressText"
        echo "That is not an Elastic IP!"
        exit 1
    fi

    # Abort if this is a VPC instance but the address is standard
    if [ -n "$vpc" ] && [ "$addressType" != "vpc" ]; then
        echo "Invalid IP address $addressText"
        echo "That is not a VPC-compatible Elastic IP!"
        exit 1
    fi

    # Abort if this is EC2 Classic but the address is for VPC
    if [ -z "$vpc" ] && [ "$addressType" = "vpc" ]; then
        echo "Invalid IP address $addressText"
        echo "That address only works for VPC instances!"
        exit 1
    fi

fi

### Cleanup Code ##############################################################

# Just in case...
unset imageId
unset instanceId
unset snapshotId
unset volumeId

cleanup() {
    echo; print_separator;
    printf "Cleaning for start_encrypted_instance\n\n"

    # Terminate the instance
    if [ -n "$instanceId" ]; then
        dots "Terminating instance $instanceId"
        $(awsapi ec2.TerminateInstances InstanceId.1=$instanceId)
        $(awsapi ec2.DescribeInstances InstanceId.1=$instanceId \
            reservationSet.1.instancesSet.1.instanceState.name \
                := shutting-down/terminated)
        echo "done"; unset instanceId
    fi

    # Deregister the image
    if [ -n "$imageId" ]; then
        dots "Deregistering image $imageId"
        $(awsapi ec2.DeregisterImage ImageId=$imageId return := true)
        echo "done"; unset imageId
    fi

    # Delete the snapshot
    if [ -n "$snapshotId" ]; then
        dots "Deleting snapshot $snapshotId"; sleep 10
        $(awsapi ec2.DeleteSnapshot SnapshotId=$snapshotId return := true)
        echo "done"; unset snapshotId
    fi

    if [ -n "$volumeId" ]; then

        $(awsapi ec2.DescribeVolumes VolumeId.1=$volumeId volumeSet.1.status)

        # Detach the volume
        if [ "$status" = "in-use" ]; then
            dots "Detaching volume $volumeId"
            $(awsapi ec2.DetachVolume VolumeId=$volumeId)
            $(awsapi ec2.DescribeVolumes VolumeId.1=$volumeId \
                volumeSet.1.status := in-use/available)
            echo "done"
        fi

        # Delete the volume
        dots "Deleting volume $volumeId"
        $(awsapi ec2.DeleteVolume VolumeId=$volumeId return := true)
        echo "done"; unset volumeId
    fi

    # We must handle this, since we're overriding the awsapi cleanup
    if [ "$AWSAPI_FILE_DIR" != "$ORIGINAL_AWSAPI_FILE_DIR" ]; then
        rm -rf "$AWSAPI_FILE_DIR"
    fi

    echo; exit $exitValue
}

trap cleanup INT EXIT

### Prepare an empty volume ###################################################

attach_volume() {
    local second

    # External device names are always /dev/sd*, not /dev/xvd*
    xdev="${dev#/dev/xvd}"
    if [ "$xdev" != "${dev}" ]; then
        xdev="/dev/sd${xdev}"
    fi

    # Attempt to attach the volume
    $(awsapi ec2.AttachVolume VolumeId=$volumeId \
        InstanceId=$workInstance Device=$xdev)
    $(awsapi ec2.DescribeVolumes VolumeId.1=$volumeId \
        volumeSet.1.status := available/in-use)

    # Print the device name
    printf "$dev"

    # Give it ten seconds to show up
    for second in 0 1 2 3 4 5 6 7 8 9; do
        if [ -e $dev ]; then return 0; fi
        sleep 1
    done

    # If it wasn't attached: detach to clean up
    if [ ! -e $dev ]; then
        $(awsapi ec2.DetachVolume VolumeId=$volumeId)
        $(awsapi ec2.DescribeVolumes VolumeId.1=$volumeId \
            volumeSet.1.status := in-use/available)
        while [ -n "$dev" ]; do dev="${dev%?}"; printf "\010"; done
        return 1
    fi

    return 0
}

# Create an empty volume and wait for it to become available
dots "Creating volume in $zone"
$(awsapi ec2.CreateVolume AvailabilityZone=$zone Size=$volumeSize volumeId)
$(awsapi ec2.DescribeVolumes VolumeId.1=$volumeId \
    volumeSet.1.status := creating/available)
    echo "$volumeId"

# Ubuntu 11.04 is using /dev/xvd* devices
if [ -e /dev/xvda -o -e /dev/xvda1 ]; then
    devPrefix=/dev/xvd
else
    devPrefix=/dev/sd
fi

# Find a suitable device and attach the volume
dots "Selecting device node"
for x in f g h i j k l m n o p; do
    dev="$devPrefix$x";
    if [ ! -e $dev ] && attach_volume; then
        echo; break;
    fi;
    if [ $x = p ]; then
        echo "No device available"
        exit 1
    fi
done

# A blank line before the next step
echo

### Create the encrypted filesystem ###########################################

# Put an encrypted filesystem on the volume
args="--trust-me$options $dev $domain $system"
$SUDO "$(dirname $0)/make_encrypted_kali.sh" $args 
print_separator;

# Detach the volume
dots "Detaching volume from instance"
$(awsapi ec2.DetachVolume VolumeId=$volumeId)
$(awsapi ec2.DescribeVolumes VolumeId.1=$volumeId \
    volumeSet.1.status := in-use/available)
    echo "done"

# Create a snapshot from the volume
dots "Creating snapshot"
text="$instanceName"
$(awsapi ec2.CreateSnapshot VolumeId=$volumeId Description="$text" snapshotId)
echo "$snapshotId"; progress="0%"; unset oldProgress

# Wait for snapshot completion
dots "Waiting for snapshot"
while true; do

    # Print the progress
    printf "%s" "${progress}"
    if [ "$progress" = "100%" ]; then
        break
    fi

    # Wait before checking the progress
    sleep 10; oldProgress="$progress"
    $(awsapi ec2.DescribeSnapshots SnapshotId.1=$snapshotId \
        snapshotSet.1.progress or "0%")

    # Erase any old progress
    while [ -n "$oldProgress" ]; do
        oldProgress="${oldProgress%?}";
        printf "\010";
    done

done

# This should be completed, but let's make sure...
$(awsapi ec2.DescribeSnapshots SnapshotId.1=$snapshotId \
    snapshotSet.1.status := pending/completed)

echo

# Delete the volume; we will work with the snapshot from now on
dots "Deleting volume bleep"
$(awsapi ec2.DeleteVolume VolumeId=$volumeId return := true)
echo "done"; unset volumeId

### Launch the instance #######################################################

# Register the image
dots "Registering image"
$(awsapi ec2.RegisterImage \
    BlockDeviceMapping.1.{ DeviceName=/dev/sda, Ebs.SnapshotId=$snapshotId } \
    Name="$instanceName" KernelId=aki-919dcaf8 RootDeviceName=/dev/sda1 \
    Architecture=$arch imageId)
    echo "$imageId"

# Wait for the image to become available
$(awsapi ec2.DescribeImages \
    Filter.1.{ Name="image-id", Value.1="$imageId" } \
    imagesSet.1.imageState := -/available)

# Launch a new instance
dots "Launching instance"
$(awsapi ec2.RunInstances ImageId=$imageId MinCount=1 MaxCount=1 \
    $params KeyName="$key" InstanceType="$type" \
    Placement.AvailabilityZone="$zone" instancesSet.1.instanceId)

# Wait for the instance to boot
$(awsapi ec2.DescribeInstances \
    Filter.1.{ Name="instance-id", Value.1="$instanceId" } \
    reservationSet.1.instancesSet.1.instanceState.name \
        := -/pending/running)

echo "$instanceId"

# Deregister the image
dots "Deregistering image"
$(awsapi ec2.DeregisterImage ImageId=$imageId return := true)
echo "done"; unset imageId

# Delete the snapshot
dots "Deleting snapshot"; sleep 10
$(awsapi ec2.DeleteSnapshot SnapshotId=$snapshotId return := true)
echo "done"; unset snapshotId

### Configure the instance ####################################################

# Get ID and IP address for the first network interface
$(awsapi ec2.DescribeNetworkInterfaces \
    Filter.1.Name=attachment.instance-id Filter.1.Value=$instanceId \
    Filter.2.Name=attachment.device-index Filter.2.Value=0 \
    networkInterfaceSet.1.{ \
        networkInterfaceId or "", \
        privateIpAddress or "" \
    } \
)

# Set a name tag
$(awsapi ec2.CreateTags ResourceId.1=$instanceId \
    Tag.1.{ Key=Name, Value="$instanceName" })

# If we have a public address to set:
if [ -n "$ipAddress" ] && $public; then
    dots "Setting IP address ($ipAddress)"
    params=""

    # Get the initial address (which may be empty for VPC)
    $(awsapi ec2.DescribeInstances InstanceId.1=$instanceId \
        reservationSet.1.instancesSet.1.{ \
            oldIpAddress:ipAddress or "-" \
        } \
    )

    # VPC likes to be different...
    if [ -n "$vpc" ]; then
        params="$params NetworkInterfaceId=$networkInterfaceId"
        params="$params AllocationId=$allocationId"
    else
        params="$params InstanceId=$instanceId"
        params="$params PublicIp=$ipAddress"
    fi

    # Associate the new address
    $(awsapi ec2.AssociateAddress $params)

    # Wait for the new address to replace the old one
    $(awsapi ec2.DescribeInstances InstanceId.1=$instanceId \
        reservationSet.1.instancesSet.1.ipAddress \
            := $oldIpAddress/$ipAddress)

    echo "done"
fi

### Display the result ########################################################

echo; print_separator;
echo "This is your new instance:"
echo

# Grab the "Name" tags for all "instance" resources
$(awsapi ec2.DescribeTags tag@resourceId+tagSet.n.{ \
    resourceId, resourceType eq instance, key eq Name, name:value \
})

# Describe the instance as a table, just to show off
$(awsapi --table ec2.DescribeInstances InstanceId.1=$instanceId \
    instance+reservationSet.1.instancesSet.1.{ \
        instanceId, state:instanceState.name, \
        zone:placement.availabilityZone, \
        ~tag.name@instanceId, ipAddress or "${privateIpAddress:--}" \
    } | sed 's/\\/\\\\/g')

# This is a good idea
domain="${domain:-${ipAddress:-${privateIpAddress:-your-server}}}"
echo "Unlock at https://${domain}/ before logging in."

# Don't terminate the instance
unset instanceId

exitValue=0

###############################################################################
