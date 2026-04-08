#!/bin/bash
tmux kill-session -t onion 2>/dev/null
PORT=50004
sudo fuser -k 50004/tcp 2>/dev/null || true
lsof -ti:$PORT | xargs -r kill
sleep 1
lsof -ti:$PORT | xargs -r kill -9

mkdir -p output
sudo chmod 777 output
rm -rf active_proxies

tmux set-option -g destroy-unattached on

tmux new-session -d -s onion -n proxy1
tmux new-window  -t onion -n proxy2
tmux new-window  -t onion -n proxy3
tmux new-window  -t onion -n server
tmux new-window  -t onion -n client
tmux new-window  -t onion -n TCPDUMP

tmux send-keys -t onion:proxy1 '.venv/bin/python3 proxy.py > output/proxy1.log 2>&1' C-m
tmux send-keys -t onion:proxy2 '.venv/bin/python3 proxy.py > output/proxy2.log 2>&1' C-m
tmux send-keys -t onion:proxy3 '.venv/bin/python3 proxy.py > output/proxy3.log 2>&1' C-m
tmux send-keys -t onion:server '.venv/bin/python3 server.py > output/server.log 2>&1' C-m
tmux send-keys -t onion:TCPDUMP 'sudo tcpdump -i any -w output/capture.pcap' C-m
tmux send-keys -t onion:client 'source .venv/bin/activate' C-m

tmux select-window -t onion:client
tmux attach-session -t onion