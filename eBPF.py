from bcc import BPF

def main():
    # Define eBPF program
    bpf_program = """
    #include <uapi/linux/ptrace.h>

    int hello_world(void *ctx) {
        bpf_trace_printk("--\\n");
        return 0;
    }
    """

    # Load and attach eBPF program
    b = BPF(text=bpf_program)
    b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello_world")

    # Setup a counter for how many times "--" is printed
    print_count = 0

    # Poll for trace print events
    while print_count < 4:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields(nonblocking=True)
        if msg:
            print_count += 1
            print("-- Printed {} times".format(print_count))

    if print_count >= 4:
        print("Success")
    else:
        print("Fail")

if __name__ == "__main__":
    main()
