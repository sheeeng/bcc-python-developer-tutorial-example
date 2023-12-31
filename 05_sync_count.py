#!/usr/bin/python
#

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0, c, *cp, count_key = 1;

    // attempt to read stored sync call count
    cp = last.lookup(&count_key);
    if (cp != NULL) {
        c = *cp;
        c++;
        last.delete(&count_key);
        // bpf_trace_printk("### %d\\n", c);
    } else {
        c = 1;
    }

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("last %d ms ago, total %llu calls.\\n", delta / 1000000, c);
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    last.update(&count_key, &c);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, ms) = b.trace_fields()
        if start == 0:
            start = ts
        ts = ts - start
        printb(b"At time %.2f s: multiple syncs detected, %s" % (ts, ms))
    except KeyboardInterrupt:
        exit()
