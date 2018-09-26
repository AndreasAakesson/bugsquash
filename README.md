# :bug: squash

Run IncludeOS router on two nets to the same host.
8 interfaces in 1 out.

## Setup second net
Do as said in https://github.com/hioa-cs/IncludeOS/pull/1910 ^^
Remember to modify qemu-if scripts to the name of your bridge, and make em executable.

## Edit vm.json
First NIC in vm.json is configured to be the out interface (on a seprate net).
Change the scripts member on the first nic to your path: `"scripts": "/Users/andreas/dev/bridge44/"`.

## NaCl
Network configuration. These makes some assumptions about iperf3.

## Run test
Run iperf3 server (make sure your second bridge is created):
```
$ iperf3 -s -p 5201& iperf3 -s -p 5202& iperf3 -s -p 5203& iperf3 -s -p 5204& iperf3 -s -p 5205& iperf3 -s -p 5206& iperf3 -s -p 5207& iperf3 -s -p 5208&
```
Connect to the servers:
```
iperf3 -c 10.0.0.101 -p 5201 -t 600 # run for 600 seconds
```
Do the same for all others, just change last number in IP and port:
```
iperf3 -c 10.0.0.102 -p 5202 -t 600 # etc etc
```

To terminate test and servers: `killall iperf3`
