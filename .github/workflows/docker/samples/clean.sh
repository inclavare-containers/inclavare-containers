crictl stopp $(crictl pods | awk 'END{print $1}')
crictl rmp $(crictl pods | awk 'END{print $1}')
