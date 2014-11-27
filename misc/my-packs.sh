cd $( dirname ${BASH_SOURCE} )

# slc6
./create-packs.sh --python-version 2.6 --iteration 1 --verbose --targets rpm

# ubuntu
./create-packs.sh --python-version 2.7 --iteration 1 --verbose --targets deb
