from bcc import BPF

kallsyms = "/proc/kallsyms"

bpf_text = open("bpf.c").read();

BPF_BUFFER_TRACE_MAGIC = 0xdeadbeefdeadbeef;

with open(kallsyms) as syms:
    ops = ''
    for line in syms:
        (addr, size, name) = line.rstrip().split(" ", 2)
        name = name.split("\t")[0]
        if name == "ext4_file_operations":
            ops = "0x" + addr
            break
    if ops == '':
        print("ERROR: no ext4_file_operations in /proc/kallsyms. Exiting.")
        print("HINT: the kernel should be built with CONFIG_KALLSYMS_ALL.")
        exit()
    bpf_text = bpf_text.replace('EXT4_FILE_OPERATIONS', ops)
    bpf_text = bpf_text.replace('BBTM', str(BPF_BUFFER_TRACE_MAGIC))

b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_read", fn_name="vfs_read_enter")
b.attach_kretprobe(event="vfs_read", fn_name="vfs_read_leave")
b.attach_kprobe(event="ext4_file_read_iter", fn_name="ext4_file_read_iter_enter")
b.attach_kretprobe(event="ext4_file_read_iter", fn_name="ext4_file_read_iter_leave")
b.attach_kprobe(event="iomap_dio_rw", fn_name="iomap_dio_rw_enter")
b.attach_kretprobe(event="iomap_dio_rw", fn_name="iomap_dio_rw_leave")
b.attach_kprobe(event="filemap_write_and_wait_range", fn_name="filemap_write_and_wait_range_enter")
b.attach_kretprobe(event="filemap_write_and_wait_range", fn_name="filemap_write_and_wait_range_leave")

def ms(ns):
    return ns / 1_000_000

def pevent(cpu, data, size):
    event = b["events"].event(data)
    span = event.vfs_read_leave_ts - event.vfs_read_enter_ts
    if span > 100_000_000: # 100ms
        start = event.vfs_read_enter_ts
        
        print("magic: ", event.magic)
        print("super_span_id: %x" % event.super_span_id)
        print("vfs_read_enter_ts: ", ms(event.vfs_read_enter_ts - start))
        print("ext4_file_read_iter_enter_ts: ", ms(event.ext4_file_read_iter_enter_ts - start))
        print("iomap_dio_rw_enter_ts: ", ms(event.iomap_dio_rw_enter_ts - start))
        print("filemap_write_and_wait_range_enter_ts: ", ms(event.filemap_write_and_wait_range_enter_ts - start))
        print("filemap_write_and_wait_range_leave_ts: ", ms(event.filemap_write_and_wait_range_leave_ts - start))
        print("iomap_dio_rw_leave_ts: ", ms(event.iomap_dio_rw_leave_ts - start))
        print("ext4_file_read_iter_leave_ts: ", ms(event.ext4_file_read_iter_leave_ts - start))
        print("vfs_read_leave_ts: ", ms(event.vfs_read_leave_ts - start))
        
        print("span: %.2fms\n%d %d %d %d %d %d %d %d" % (
            ms(span),
            event.vfs_read_enter_ts,
            event.vfs_read_leave_ts,
            event.ext4_file_read_iter_enter_ts,
            event.ext4_file_read_iter_leave_ts,
            event.iomap_dio_rw_enter_ts,
            event.iomap_dio_rw_leave_ts,
            event.filemap_write_and_wait_range_enter_ts,
            event.filemap_write_and_wait_range_leave_ts,
        ))

b["events"].open_perf_buffer(pevent)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
