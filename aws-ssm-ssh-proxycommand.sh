#!/usr/bin/env bash
#
# Description
# Bootstrap SSH Session to an SSM-managed instance
# by temporarily adding a public SSH key available on the local machine (ssh-agent or in ~/.ssh)
# 
#
# Installation
#
# First run your eye over this script to check for malicious code
# Then run this script without arguments to automatically perform all install steps on your client:
#
#   curl -s 'https://raw.githubusercontent.com/intelematics/aws-ssm-ssh-proxycommand/master/aws-ssm-ssh-proxycommand.sh' | bash
#
# It will:
#
# #1 Install the AWS CLI
#   https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html
#
# #2 Install the Session Manager Plugin for the AWS CLI
#   https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html
#
# #3 Install this script
#  	- Move this script to ~/.ssh/aws-ssm-ec2-proxy-command.sh
#  	- Make it executable (chmod +x ~/.ssh/aws-ssm-ec2-proxy-command.sh)
#
# #4 Update your SSH config to use this script as ProxyCommand when SSH'ing to EC2 instances:
#  		Host i-* mi-* jumpbox
#  			ProxyCommand ~/.ssh/aws-ssm-ec2-proxy-command.sh %h %r %p
#			StrictHostKeyChecking no
#
#
# Host Requirements
#
# #1 Ensure SSM Permissions of Target Instance Profile
#
#   https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-instance-profile.html
#
# #2 Ensure latest SSM Agent on Target Instance
#
#   Is preinstalled on all amazon linux AMIs, however may needs to be updated
#   yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm & service amazon-ssm-agent restart
#   or
#   aws ssm send-command --instance-ids i-xxxxxxxxxx --document-name AWS-UpdateSSMAgent
#
# #3 (optional) name the host "jumpbox"
# Then if you "ssh jumpbox" you'll connect to it, instead of using instance IDs
#
#
# Example Usage
#
#	ssh ec2-user@i-xxxxxxxxxx
#	ssh ubuntu@jumpbox
#	ssh -N -L 5432:myrds.cunh7nydpqk3.ap-southeast-2.rds.amazonaws.com:5432 ubuntu@i-xxjumpboxx
#
#
# TODO
# Possibly - replace the SSH key provisioning with ec2 instance connect
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-set-up.html
# Although 'neater' and using an official AWS Service,
# this does increase requirements to having EC2 instance connect installed (scripts + sshd config AuthorizedKeysCommand)
# And adding relevant IAM perms to the accessing role (ec2-instance-connect:SendSSHPublicKey)
#
################################################################################

DEFAULT_SSH_PUBLIC_KEY_PATHS="${HOME}/.ssh/id_rsa.pub ${HOME}/.ssh/id_ed25519.pub"
SSH_PUBLIC_KEY_TIMEOUT=5
SSH_USER_DEFAULT=ec2-user
SSH_PORT_DEFAULT=22
THIS_SCRIPT_URL="https://raw.githubusercontent.com/intelematics/aws-ssm-ssh-proxycommand/master/aws-ssm-ssh-proxycommand.sh"

# Convnience feature to enable just "ssh jumpbox" (instead of instance id)
# We then find the first ec2 instance with name tag = "jumpbox"
# and connect to that
MAGIC_JUMPBOX_INSTANCE_NAME="jumpbox"


main() {

	args=($@)
	local cmd=${args[0]-install}
	local install_location=${args[1]-~/.ssh/aws-ssm-ec2-proxy-command.sh}
	local ec2_instance_id=${args[0]}
	local ssh_user=${args[1]-$SSH_USER_DEFAULT}
	local ssh_port=${args[2]-$SSH_PORT_DEFAULT}

	usage="
Usage:\n
  aws-ssm-ec2-proxy-command.sh install [install-location (default ~/.ssh)]\n
  aws-ssm-ec2-proxy-command.sh i-xxxxxxx [ssh-username] [ssh-port]\n
"
	if [[ "install" == $cmd ]] ; then
		echo
		echo
		install $install_location
		if [[ 0 != $? ]] ; then
			echo "Problem installing - bailing"
			exit $?
		fi
		exit 0
	else 
		if [[ -z $ec2_instance_id ]] ; then
			echo -e $usage
			exit 1
		fi
		connect $ec2_instance_id $ssh_user $ssh_port
		exit 0
	fi
}


install_aws_cli() {
	if [[ -n `which aws` ]] ; then
		return
	fi
	echo
	echo "Installing AWS CLI ..."

	if [[ -n `which python3` ]] ; then
		sudo pip3 install --prefix=/usr/local awscli
	elif [[ -n `which python` ]] ; then
		sudo pip install --prefix=/usr/local awscli
	else
		echo "You need python installed!"
		exit 1
	fi
	echo
}


install_aws_cli_session_manager_plugin() {
	if [[ -n `which session-manager-plugin` ]] ; then
		return
	fi
	echo "Installing AWS CLI session-manager-plugin ..."
	uname=`uname -a`
	if [[ -n `echo $uname | grep Darwin` ]] ; then
		curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/mac/sessionmanager-bundle.zip" -o "/tmp/sessionmanager-bundle.zip"
		unzip -d /tmp/ /tmp/sessionmanager-bundle.zip
		sudo /tmp/sessionmanager-bundle/install -i /usr/local/sessionmanagerplugin -b /usr/local/bin/session-manager-plugin
		rm /tmp/session-manager-plugin-bundle.zip
	elif [[ -n `echo $uname | grep Ubuntu` || -n `echo $uname | grep "^Linux.*Microsoft"` ]] ; then
		curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "/tmp/session-manager-plugin.deb"
		sudo dpkg -i /tmp/session-manager-plugin.deb
		rm /tmp/session-manager-plugin.deb
	else
		echo "Don't know how to install session-manager-plugin for your system - please do so manually then try again. Refer here for instructions: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html"
		exit 1
	fi
}


install() {
	local install_location=$1

	install_aws_cli
	install_aws_cli_session_manager_plugin

	mkdir -p `dirname $install_location`

	curl -s $THIS_SCRIPT_URL > $install_location
	if [[ 0 != $? ]] ; then
		echo "Couldn't download script from $THIS_SCRIPT_URL - bailing"
		exit $?
	fi
	chmod +x $install_location

	# Update ssh config, if needed
	if [[ -z `grep 'Host i-\*' ~/.ssh/config` ]] ; then
		echo "Updating ~/.ssh/config to use the script as ProxyCommand for 'ssh i-*'"
		echo "
Host i-* mi-* ${MAGIC_JUMPBOX_INSTANCE_NAME}
	User ${SSH_USER_DEFAULT}
	ProxyCommand ${install_location} %h %r %p
	StrictHostKeyChecking no
" >> ~/.ssh/config
	fi

	echo "Installed to ${install_location}"
}


get_ssh_public_key() {
	# Try to get an public ssh key from 'ssh agent'
	ssh_public_key="$(keys="$(ssh-add -L 2>/dev/null)" && echo $keys | head -1)"
	if [[ -n "$ssh_public_key" ]]; then
		ssh_public_key_source='ssh agent'
	else
		# Try read public ssh key from '${DEFAULT_SSH_PUBLIC_KEY_PATHS}'
		for ssh_public_key_path in $DEFAULT_SSH_PUBLIC_KEY_PATHS; do
			ssh_public_key="$([[ -e "${ssh_public_key_path}" ]] && cat "${ssh_public_key_path}")"
			if [[ -n "$ssh_public_key" ]]; then
				ssh_public_key_source="${ssh_public_key_path}"
			fi
		done
	fi

	# Try getting ANY ssh key in ~/.ssh
	# If found - start ssh-agent and add it
	if [[ -z "${ssh_public_key}" ]]; then
		for ssh_public_key_path in $(ls ~/.ssh/*.pub 2>/dev/null); do
			# Check we have (what looks like) the corresponding private key
			ssh_private_key_path="$(dirname $ssh_public_key_path)/$(basename $ssh_public_key_path .pub)"
			if [[ -e "$ssh_private_key_path" ]] ; then
				ssh_public_key="$(cat ${ssh_public_key_path})"
				ssh-agent
				echo "Adding ${ssh_private_key_path} to ssh-agent ..."
				ssh-add ${ssh_private_key_path}
				break
			fi
		done
	fi

	if [[ -z "$ssh_public_key" ]]; then
		echo "No ssh key present in ssh agent nor ~/.ssh/"
	exit 1
	fi

	echo $ssh_public_key
}


get_ec2_instance_id_for_name() {
	local instance_name=$1

	instance_id=`aws ec2 describe-instances --filters "Name=tag:Name,Values=${MAGIC_JUMPBOX_INSTANCE_NAME}" --query "Reservations[].Instances[].InstanceId" --output text`
	echo $instance_id
}


connect() {
	local ec2_instance_id=$1
	local ssh_user=$2
	local ssh_port=$3
	local ssh_public_key=$(get_ssh_public_key)

	if [[ ${ec2_instance_id} == ${MAGIC_JUMPBOX_INSTANCE_NAME} ]] ; then
		ec2_instance_id=`get_ec2_instance_id_for_name ${ec2_instance_id}`
		if [[ -z "$ec2_instance_id" ]] ; then
			echo "Couldn't get instance ID for host named '${MAGIC_JUMPBOX_INSTANCE_NAME}' - ensure you have one in your account"
			exit 1
		fi
	fi

	aws ssm send-command \
		--instance-ids "${ec2_instance_id}" \
		--document-name 'AWS-RunShellScript' \
		--parameters commands="\"
			sudo su
			mkdir -p ~${ssh_user}/.ssh
			chown -R ${ssh_user}:${ssh_user} ~${ssh_user}/.ssh
			cd ~${ssh_user}/.ssh || exit 1
			grep -F '${ssh_public_key}' authorized_keys || echo '${ssh_public_key} ssm-session' >> authorized_keys
			sleep ${SSH_PUBLIC_KEY_TIMEOUT}
			grep -v -F '${ssh_public_key}' authorized_keys > .tmp.authorized_keys
			mv .tmp.authorized_keys authorized_keys
		\"" \
		--comment "grant ssh access for ${SSH_PUBLIC_KEY_TIMEOUT} seconds"

	# Start SSM SSH session
	aws ssm start-session \
		--target "${ec2_instance_id}" \
		--document-name "AWS-StartSSHSession" \
		--parameters "portNumber=${ssh_port}"
}

main "$@"
