#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/blk-mq.h>

#define PMAX 128

#define BPF_BUFFER_TRACE_MAGIC BBTM

// tss
BPF_HASH(vfs_read_enter_tss, u64, u64);
BPF_HASH(vfs_read_leave_tss, u64, u64);
BPF_HASH(ext4_file_read_iter_enter_tss, u64, u64);
BPF_HASH(ext4_file_read_iter_leave_tss, u64, u64);
BPF_HASH(iomap_dio_rw_enter_tss, u64, u64);
BPF_HASH(iomap_dio_rw_leave_tss, u64, u64);
BPF_HASH(filemap_write_and_wait_range_enter_tss, u64, u64);
BPF_HASH(filemap_write_and_wait_range_leave_tss, u64, u64);
BPF_HASH(magics, u64, u64);
BPF_HASH(super_span_ids, u64, u64);

struct data_t {
    u64 magic;
    u64 super_span_id;
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

static void output(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    u64 magic = 0;
    u64 super_span_id = 0;
    u64 vfs_read_enter_ts = 0;
    u64 vfs_read_leave_ts = 0;
    u64 ext4_file_read_iter_enter_ts = 0;
    u64 ext4_file_read_iter_leave_ts = 0;
    u64 iomap_dio_rw_enter_ts = 0;
    u64 iomap_dio_rw_leave_ts = 0;
    u64 filemap_write_and_wait_range_enter_ts = 0;
    u64 filemap_write_and_wait_range_leave_ts = 0;

    u64 *p_magic = magics.lookup(&id);
    if (p_magic) magic = *p_magic;
    u64 *p_super_span_id = super_span_ids.lookup(&id);
    if (p_super_span_id) super_span_id = *p_super_span_id;
    u64 *p_vfs_read_enter_ts = vfs_read_enter_tss.lookup(&id);
    if (p_vfs_read_enter_ts) vfs_read_enter_ts = *p_vfs_read_enter_ts;
    u64 *p_vfs_read_leave_ts = vfs_read_leave_tss.lookup(&id);
    if (p_vfs_read_leave_ts) vfs_read_leave_ts = *p_vfs_read_leave_ts;
    u64 *p_ext4_file_read_iter_enter_ts = ext4_file_read_iter_enter_tss.lookup(&id);
    if (p_ext4_file_read_iter_enter_ts) ext4_file_read_iter_enter_ts = *p_ext4_file_read_iter_enter_ts;
    u64 *p_ext4_file_read_iter_leave_ts = ext4_file_read_iter_leave_tss.lookup(&id);
    if (p_ext4_file_read_iter_leave_ts) ext4_file_read_iter_leave_ts = *p_ext4_file_read_iter_leave_ts;
    u64 *p_iomap_dio_rw_enter_ts = iomap_dio_rw_enter_tss.lookup(&id);
    if (p_iomap_dio_rw_enter_ts) iomap_dio_rw_enter_ts = *p_iomap_dio_rw_enter_ts;
    u64 *p_iomap_dio_rw_leave_ts = iomap_dio_rw_leave_tss.lookup(&id);
    if (p_iomap_dio_rw_leave_ts) iomap_dio_rw_leave_ts = *p_iomap_dio_rw_leave_ts;
    u64 *p_filemap_write_and_wait_range_enter_ts = filemap_write_and_wait_range_enter_tss.lookup(&id);
    if (p_filemap_write_and_wait_range_enter_ts) filemap_write_and_wait_range_enter_ts = *p_filemap_write_and_wait_range_enter_ts;
    u64 *p_filemap_write_and_wait_range_leave_ts = filemap_write_and_wait_range_leave_tss.lookup(&id);
    if (p_filemap_write_and_wait_range_leave_ts) filemap_write_and_wait_range_leave_ts = *p_filemap_write_and_wait_range_leave_ts;

    vfs_read_enter_tss.delete(&id);
    vfs_read_leave_tss.delete(&id);
    ext4_file_read_iter_enter_tss.delete(&id);
    ext4_file_read_iter_leave_tss.delete(&id);
    iomap_dio_rw_enter_tss.delete(&id);
    iomap_dio_rw_leave_tss.delete(&id);
    filemap_write_and_wait_range_enter_tss.delete(&id);
    filemap_write_and_wait_range_leave_tss.delete(&id);
    magics.delete(&id);


    struct data_t data = {
        .magic = magic,
        .super_span_id = super_span_id,
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
    u64 id = bpf_get_current_pid_tgid();

    unsigned char target[] = "cache\x0";

    u64 ts = bpf_ktime_get_ns();

    if ((u64)file->f_op != (u64)EXT4_FILE_OPERATIONS) return 0;
    
    if (!scmp(&file->f_path.dentry->d_iname[0], &target[0])) return 0;

    u64 magic = *((u64 *)buf);

    u64 super_span_id = *(((u64 *)buf) + 1);

    vfs_read_enter_tss.update(&id, &ts);
    magics.update(&id, &magic);
    super_span_ids.update(&id, &super_span_id);

    return 0;
}

int vfs_read_leave(struct pt_regs *ctx, struct file *file, char *buf, size_t count, long long *pos) {
    u64 id = bpf_get_current_pid_tgid();

    u64 ts = bpf_ktime_get_ns();
    
    u64 *ets = vfs_read_enter_tss.lookup(&id);
    if (ets == 0) return 0;

    vfs_read_leave_tss.update(&id, &ts);

    output(ctx);
    
    return 0;
}

int ext4_file_read_iter_enter(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *to) {
    u64 id = bpf_get_current_pid_tgid();
    
    u64 ts = bpf_ktime_get_ns();

    u64 *pts = vfs_read_enter_tss.lookup(&id);
    if (pts == 0) return 0;

    ext4_file_read_iter_enter_tss.update(&id, &ts);

    return 0;
}

int ext4_file_read_iter_leave(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *to) {
    u64 id = bpf_get_current_pid_tgid();
    
    u64 ts = bpf_ktime_get_ns();
    
    if (ext4_file_read_iter_enter_tss.lookup(&id) == 0) return 0;

    ext4_file_read_iter_leave_tss.update(&id, &ts);
    
    return 0;
}

int iomap_dio_rw_enter(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *iter) {
    u64 id = bpf_get_current_pid_tgid();
    
    u64 ts = bpf_ktime_get_ns();

    u64 *pts = vfs_read_enter_tss.lookup(&id);
    if (pts == 0) return 0;

    iomap_dio_rw_enter_tss.update(&id, &ts);

    return 0;
}

int iomap_dio_rw_leave(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *iter) {
    u64 id = bpf_get_current_pid_tgid();
    
    u64 ts = bpf_ktime_get_ns();

    if (iomap_dio_rw_enter_tss.lookup(&id) == 0) return 0;
    iomap_dio_rw_leave_tss.update(&id, &ts);

    return 0;
}

int filemap_write_and_wait_range_enter(struct pt_regs *ctx, struct address_space *mapping, long long lstart, long long lend) {
    u64 id = bpf_get_current_pid_tgid();
    
    u64 ts = bpf_ktime_get_ns();

    if (iomap_dio_rw_enter_tss.lookup(&id) == 0) return 0;
    filemap_write_and_wait_range_enter_tss.update(&id, &ts);

    return 0;
}

int filemap_write_and_wait_range_leave(struct pt_regs *ctx, struct address_space *mapping, long long lstart, long long lend) {
    u64 id = bpf_get_current_pid_tgid();
    
    u64 ts = bpf_ktime_get_ns();

    if (filemap_write_and_wait_range_enter_tss.lookup(&id) == 0) return 0;

    filemap_write_and_wait_range_leave_tss.update(&id, &ts);
    
    return 0;
}