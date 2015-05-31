#!/bin/bash

# docker-entrypoint.sh -- by Dario Berzano <dario.berzano@cern.ch>
#
# Entrypoint for a generic Debian- or RHEL-based Docker container for installing and testing
# elastiq. Drops into a shell when finished installing

package="$1"
ext=${package##*.}

if [[ $ext == deb ]] ; then
  dpkg -i "$package" || exit 1
elif [[ $ext == rpm ]] ; then
  rpm -ihv "$package" || exit 1
else
  echo "You must provide a .rpm or .deb package as argument."
  exit 2
fi

sconf="$(dirname "$0")/elastiq.conf"
econf='/etc/elastiq.conf'
if [[ -e "$sconf" ]] ; then
  echo '--> Applying new configuration'
  cat "$sconf" > "$econf"
fi

echo '--> Exporting EC2 variables'
function get_var() (
  cat "$econf" | grep "$1" | sed -e "s|^\s*$1\s*=\s*||"
)
export EC2_URL=$(get_var api_url)
export EC2_ACCESS_KEY=$(get_var aws_access_key_id)
export EC2_SECRET_KEY=$(get_var aws_secret_access_key)

echo '--> Creating fake condor stuff'
cat > /usr/bin/condor_q <<EOF
#!/bin/bash
echo JobStatus = 1
EOF
cat > /usr/bin/condor_status <<EOF
#!/bin/bash
cat <<_EoF_
<?xml version="1.0"?>
<!DOCTYPE classads SYSTEM "classads.dtd">
<classads>
</classads>
_EoF_
EOF
chmod +x /usr/bin/condor_{q,status}

echo '--> Setting elastiq state'
st=/var/lib/elastiq/state
cat > "$st" <<_EoF_
i-00149e77
_EoF_
chown elastiq:elastiq "$st"

echo '--> Running elastiq'
service elastiq start

echo '--> Dropping into an interactive shell'
exec bash
