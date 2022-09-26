#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/blk-mq.h>

#define PMAX 128

// tss
BPF_HASH(vfs_read_enter_tss, u64, u64);
BPF_HASH(vfs_read_leave_tss, u64, u64);
BPF_HASH(ext4_file_read_iter_enter_tss, u64, u64);
BPF_HASH(ext4_file_read_iter_leave_tss, u64, u64);
BPF_HASH(iomap_dio_rw_enter_tss, u64, u64);
BPF_HASH(iomap_dio_rw_leave_tss, u64, u64);
BPF_HASH(filemap_write_and_wait_range_enter_tss, u64, u64);
BPF_HASH(filemap_write_and_wait_range_leave_tss, u64, u64);

// mappings
BPF_HASH(f_mapping_buf, u64, u64);

struct data_t {
    u64 addr;
    u64 vfs_read_enter_ts;
    u64 vfs_read_leave_ts;
    u64 ext4_file_read_iter_enter_ts;
    u64 ext4_file_read_iter_leave_ts;
    u64 iomap_dio_rw_enter_ts;
    u64 iomap_dio_rw_leave_ts;
    u64 filemap_write_and_wait_range_enter_ts;
    u64 filemap_write_and_wait_range_leave_ts;
};

BPF_PERF_OUTPUT(events);

static void output(struct pt_regs *ctx, u64 addr) {
    u64 vfs_read_enter_ts = 0;
    u64 vfs_read_leave_ts = 0;
    u64 ext4_file_read_iter_enter_ts = 0;
    u64 ext4_file_read_iter_leave_ts = 0;
    u64 iomap_dio_rw_enter_ts = 0;
    u64 iomap_dio_rw_leave_ts = 0;
    u64 filemap_write_and_wait_range_enter_ts = 0;
    u64 filemap_write_and_wait_range_leave_ts = 0;

    u64 *p_vfs_read_enter_ts = vfs_read_enter_tss.lookup(&addr);
    if (p_vfs_read_enter_ts) vfs_read_enter_ts = *p_vfs_read_enter_ts;
    u64 *p_vfs_read_leave_ts = vfs_read_leave_tss.lookup(&addr);
    if (p_vfs_read_leave_ts) vfs_read_leave_ts = *p_vfs_read_leave_ts;
    u64 *p_ext4_file_read_iter_enter_ts = ext4_file_read_iter_enter_tss.lookup(&addr);
    if (p_ext4_file_read_iter_enter_ts) ext4_file_read_iter_enter_ts = *p_ext4_file_read_iter_enter_ts;
    u64 *p_ext4_file_read_iter_leave_ts = ext4_file_read_iter_leave_tss.lookup(&addr);
    if (p_ext4_file_read_iter_leave_ts) ext4_file_read_iter_leave_ts = *p_ext4_file_read_iter_leave_ts;
    u64 *p_iomap_dio_rw_enter_ts = iomap_dio_rw_enter_tss.lookup(&addr);
    if (p_iomap_dio_rw_enter_ts) iomap_dio_rw_enter_ts = *p_iomap_dio_rw_enter_ts;
    u64 *p_iomap_dio_rw_leave_ts = iomap_dio_rw_leave_tss.lookup(&addr);
    if (p_iomap_dio_rw_leave_ts) iomap_dio_rw_leave_ts = *p_iomap_dio_rw_leave_ts;
    u64 *p_filemap_write_and_wait_range_enter_ts = filemap_write_and_wait_range_enter_tss.lookup(&addr);
    if (p_filemap_write_and_wait_range_enter_ts) filemap_write_and_wait_range_enter_ts = *p_filemap_write_and_wait_range_enter_ts;
    u64 *p_filemap_write_and_wait_range_leave_ts = filemap_write_and_wait_range_leave_tss.lookup(&addr);
    if (p_filemap_write_and_wait_range_leave_ts) filemap_write_and_wait_range_leave_ts = *p_filemap_write_and_wait_range_leave_ts;

    struct data_t data = {
        .addr = addr,
        .vfs_read_enter_ts = vfs_read_enter_ts,
        .vfs_read_leave_ts = vfs_read_leave_ts,
        .ext4_file_read_iter_enter_ts = ext4_file_read_iter_enter_ts,
        .ext4_file_read_iter_leave_ts = ext4_file_read_iter_leave_ts,
        .iomap_dio_rw_enter_ts = iomap_dio_rw_enter_ts,
        .iomap_dio_rw_leave_ts = iomap_dio_rw_leave_ts,
        .filemap_write_and_wait_range_enter_ts = filemap_write_and_wait_range_enter_ts,
        .filemap_write_and_wait_range_leave_ts = filemap_write_and_wait_range_leave_ts,
    };
    events.perf_submit(ctx, &data, sizeof(data));
}


static bool scmp(unsigned char *s1, unsigned char *s2) {
    char *c1 = s1, *c2 = s2;
    while (*c1 != 0 && *c2 != 0 && *c1 == *c2) {
        c1++; c2++;
    }
    if (*c1 == 0 && *c2 == 0) return true;
    return false;
}

int vfs_read_enter(struct pt_regs *ctx, struct file *file, char *buf, size_t count, long long *pos) {
    unsigned char target[] = "cache\x0";

    u64 ts = bpf_ktime_get_ns();

    if ((u64)file->f_op != (u64)EXT4_FILE_OPERATIONS) return 0;
    
    if (!scmp(&file->f_path.dentry->d_iname[0], &target[0])) return 0;
    
    // bpf_trace_printk("ext4_op_read: file: %s, buf: 0x%x", file->f_path.dentry->d_iname, buf);

    u64 addr = (u64)buf;
    vfs_read_enter_tss.update(&addr, &ts);

    // output(ctx, addr);
    // bpf_trace_printk("ts: %llu, &ts: 0x%x", ts, &ts);
    
    // bpf_trace_printk("ext4_op_read: file: %s, buf: 0x%x", file->f_path.dentry->d_iname, buf);

    return 0;
}

int vfs_read_leave(struct pt_regs *ctx, struct file *file, char *buf, size_t count, long long *pos) {
    u64 ts = bpf_ktime_get_ns();
    
    u64 addr = (u64)buf;
    u64 *ets = vfs_read_enter_tss.lookup(&addr);
    if (ets == 0) return 0;

    vfs_read_leave_tss.update(&addr, &ts);

    output(ctx, addr);
    
    return 0;
}

int ext4_file_read_iter_enter(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *to) {
    u64 ts = bpf_ktime_get_ns();

    u64 addr = (u64)to->iov->iov_base;
    u64 *pts = vfs_read_enter_tss.lookup(&addr);
    if (pts == 0) return 0;

    ext4_file_read_iter_enter_tss.update(&addr, &ts);
    
    // bpf_trace_printk("pts: %llu, ts: %llu, delta: %llu", *pts, ts, (ts - *pts));


    // bpf_trace_printk("vfs_read_enter_ts: %d, ext4_file_read_iter_enter_ts: %d", ts, vfs_read_enter_ts);
    return 0;
}

int ext4_file_read_iter_leave(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *to) {
    u64 ts = bpf_ktime_get_ns();
    
    u64 addr = (u64)to->iov->iov_base;
    if (ext4_file_read_iter_enter_tss.lookup(&addr) == 0) return 0;
    ext4_file_read_iter_leave_tss.update(&addr, &ts);
    
    return 0;
}

int iomap_dio_rw_enter(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *iter) {
    u64 ts = bpf_ktime_get_ns();

    u64 addr = (u64)iter->iov->iov_base;
    u64 *pts = vfs_read_enter_tss.lookup(&addr);
    if (pts == 0) return 0;

    // bpf_trace_printk("pts: %llu, ts: %llu, delta: %llu", *pts, ts, (ts - *pts));

    iomap_dio_rw_enter_tss.update(&addr, &ts);
    u64 fmaddr = (u64)iocb->ki_filp->f_mapping;
    f_mapping_buf.update(&fmaddr, &addr);

    // bpf_trace_printk("fmaddr: 0x%x, addr: 0x%x", fmaddr, addr);
    // bpf_trace_printk("IOCB_NOWAIT: %d", iocb->ki_flags & IOCB_NOWAIT);

    return 0;
}

int iomap_dio_rw_leave(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *iter) {
    u64 ts = bpf_ktime_get_ns();

    u64 addr = (u64)iter->iov->iov_base;
    if (iomap_dio_rw_enter_tss.lookup(&addr) == 0) return 0;
    iomap_dio_rw_leave_tss.update(&addr, &ts);

    return 0;
}

int filemap_write_and_wait_range_enter(struct pt_regs *ctx, struct address_space *mapping, long long lstart, long long lend) {
    u64 ts = bpf_ktime_get_ns();

    u64 fmaddr = (u64)mapping;
    u64 *addr = f_mapping_buf.lookup(&fmaddr);
    if (addr == 0) return 0;

    filemap_write_and_wait_range_enter_tss.update(addr, &ts);

    // bpf_trace_printk("ts: %llu", ts);

    // bpf_trace_printk("pts: %llu, ts: %llu, delta: %llu", *pts, ts, (ts - *pts));

    // iomap_dio_rw_enter_tss.update(&addr, &ts);

    // bpf_trace_printk("IOCB_NOWAIT: %d", iocb->ki_flags & IOCB_NOWAIT);

    return 0;
}

int filemap_write_and_wait_range_leave(struct pt_regs *ctx, struct address_space *mapping, long long lstart, long long lend) {
    u64 ts = bpf_ktime_get_ns();

    u64 fmaddr = (u64)mapping;
    u64 *addr = f_mapping_buf.lookup(&fmaddr);
    if (addr == 0) return 0;

    filemap_write_and_wait_range_leave_tss.update(addr, &ts);
    
    return 0;
}