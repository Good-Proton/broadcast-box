#!/usr/bin/env sh

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 <whip_endpoint> <auth_token> [testsrc|v4l2]" >&2
  exit 1
fi

whip_endpoint=$1
auth_token=$2
stream_type=${3:-testsrc}

if [ "$stream_type" = "testsrc" ]; then
  srcelem="videotestsrc pattern=smpte-rp-219"
  audioelem="audiotestsrc wave=8"
else
  srcelem="v4l2src device=/dev/video1"
  audioelem="pulsesrc device=alsa_input.usb-MACROSILICON_USB3._0_capture-02.analog-stereo"
fi

gst-launch-1.0 -v \
  $srcelem \
  ! videoconvert \
  ! x264enc tune=zerolatency \
  ! rtph264pay \
  ! "application/x-rtp,media=video,encoding-name=H264,payload=97,clock-rate=90000" \
  ! whip0.sink_0 \
  $audioelem \
  ! audioconvert \
  ! opusenc \
  ! rtpopuspay \
  ! "application/x-rtp,media=audio,encoding-name=OPUS,payload=96,clock-rate=48000,encoding-params=(string)2" \
  ! whip0.sink_1 \
  whipsink \
    name=whip0 \
    use-link-headers=true \
    whip-endpoint="$whip_endpoint" \
    auth-token="$auth_token"
