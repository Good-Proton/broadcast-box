#!/usr/bin/env sh

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <whep_endpoint> <whep_token> <rtmp_location>" >&2
  exit 1
fi

whep_endpoint=$1
whep_token=$2
rtmp_location=$3

gst-launch-1.0 \
  flvmux \
    streamable=true \
    name=flvmux \
  ! rtmpsink \
    location="$rtmp_location" \
  whepsrc \
    name=whep \
    auth-token="$whep_token" \
    whep-endpoint="$whep_endpoint" \
    video-caps="application/x-rtp,payload=127,encoding-name=H264,media=video,clock-rate=90000" \
    audio-caps="application/x-rtp,payload=96,encoding-name=OPUS,media=audio,clock-rate=48000" \
  ! rtpopusdepay \
  ! fakesink \
  whep. \
  ! rtph264depay \
  ! h264parse \
  ! queue \
  ! flvmux.
