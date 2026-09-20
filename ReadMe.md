This is a standalone application.

1)Day 1

========== Collect Firewall Information ==========

we collect firewall deatails from linux machine and get current firewall state.we compare that state with our security policy.Then we decide Pass or Voilation. 

def get_firewall_information():The method which collect firewall informations from linux.

def get_Input_policy(): This ask linux specially about INPUT chain.

INPUT = traffic coming into this Linux machine.
OUTPUT = traffic leaving this Linux machine.
FORWARD = traffic passing THROUGH this Linux machine to another machine.


suppose another computer try ssh to my machine and if i have Chain INPUT (policy ACCEPT) that means by default incoming fraffic is allowed to my machine.
if Chain INPUT (policy DROP) incoming traffic block unless another firewall rule allows it.


def check_input_policy(get_input,expect): compare what default machine allowd or drop and what's our policy .


2)Day 2

Now we allow actual firewall rule for our linux machine.simply we add rule to INPUT chain allow TCP traffic to destination port 22

sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

Chain INPUT (policy ACCEPT 95 packets, 102K bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
