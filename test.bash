#!/usr/bin/env bash

# This bash script tests the outputs of passphrase2pgp against both
# GnuPG and OpenSSH. You will need the go, gpg, gpgv, and ssh-keygen
# commands on your path before running this script.

set -euo pipefail

export REALNAME="John Doe"
export EMAIL="john.doe@example.com"
export KEYID="2536A19C9C54880A8FEBC812070B00717FCDEE34"
passphrase="foobar"

go test
go build

homedir=$(mktemp -d homedir.XXXXXX)
chmod 700 $homedir
cleanup() {
    rm -rf $homedir
}
trap cleanup INT TERM EXIT
gpg="gpg --quiet --homedir $homedir"
gpgv="gpgv --quiet --homedir $homedir"

echo === Testing Unprotected PGP Keys ===
./passphrase2pgp -K --input <(echo $passphrase) \
                    --armor | \
    tee $homedir/seckey.asc
./passphrase2pgp -K --load $homedir/seckey.asc \
                    --public \
    > $homedir/trustedkeys.kbx

echo === Testing PGP Signatures ===
echo hello | \
    tee /dev/stderr | \
    ./passphrase2pgp -T --load $homedir/seckey.asc | $gpgv
echo message > $homedir/message
./passphrase2pgp -S --load $homedir/seckey.asc $homedir/message
$gpgv $homedir/message.sig $homedir/message
./passphrase2pgp -S --load $homedir/seckey.asc --armor $homedir/message
$gpgv $homedir/message.asc $homedir/message

echo === Testing Protected PGP Keys ===
./passphrase2pgp -K --input <(echo $passphrase) \
                    --protect \
                    --armor \
    | tee $homedir/seckey.s2k.asc
$gpg --passphrase-file <(echo $passphrase) \
     --pinentry-mode loopback \
     --import $homedir/seckey.s2k.asc

echo === Testing Subkeys ===
./passphrase2pgp -K --input <(echo $passphrase) \
                    --subkey \
                    --armor \
    | tee $homedir/secsub.asc
./passphrase2pgp -K --load $homedir/secsub.asc \
                    --subkey \
                    --public \
                    --armor \
    | tee $homedir/pubsub.asc
$gpg --import $homedir/pubsub.asc
echo Meet at midnight > $homedir/message.txt
$gpg --trust-model always \
     --recipient "$REALNAME" \
     --encrypt $homedir/message.txt
$gpg --import $homedir/secsub.asc
$gpg --decrypt $homedir/message.txt.gpg

echo === Testing SSH Keys ===
./passphrase2pgp -K --uid doe@exmaple.com \
                    --check '' \
                    --format ssh \
                    --input <(echo $passphrase) \
                    --protect | \
    (umask 077; tee $homedir/id_ed25519)
ssh-keygen -y -P $passphrase -f $homedir/id_ed25519 | \
    tee $homedir/id_ed25519.pub
./passphrase2pgp -K --uid john@exmaple.com \
                    --check '' \
                    --format ssh \
                    --input <(echo $passphrase) | \
    (umask 077; tee $homedir/id_ed25519x)
ssh-keygen -y -P '' -f $homedir/id_ed25519x | \
    tee $homedir/id_ed25519x.pub

echo === All Tests Passed ===
