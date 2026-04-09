# Testing Instructions
Start the container
First time (create container), Run:
    docker build -t <imagename> .
    Get container ID: docker ps -a
    docker run -it <imagename>
Reusing the container, Run:
    docker start <container_id>
    docker exec -it <container_id> bash
Once inside the container, Run:
    ./run.sh
    This starts the server, proxies, and tmux session.
To switch tmux window:
    Press Ctrl + B, then S
    Use arrow keys to navigate different tmux windows
In the tmux client window, Run:
    python client.py > output/client.log 2>&1
    Make sure the active_proxies folder is empty inside the container and the server and proxies are actually running in the tmux session.
Kill the Tmux session
    Run: tmux kill-session -t onion
    Alternative (Manual clean up)
        Press Ctrl + C to stop processes
        Press Ctrl + D to exit tmux windows
Run this outside the container in a separate terminal (without exiting the original terminal) to copy the output into the current directory:
    docker cp <container_id>:/app/output/ .
Output folder contains:
    Client, Proxy, and Server logs
    .pcap file from tcpdump
