#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate libc;

const IFNAMSIZ: usize = 16;
const IOC_IN: libc::c_ulong = 0x80000000;
const IOC_OUT: libc::c_ulong = 0x40000000;
const IOC_NONE: libc::c_ulong = 0x20000000;
const IOC_INOUT: libc::c_ulong = IOC_IN | IOC_OUT;
const IOCPARM_SHIFT: libc::c_ulong = 13;
const IOCPARM_MASK: libc::c_ulong = (1 << (IOCPARM_SHIFT as usize)) - 1;

const SIZEOF_TIMEVAL: libc::c_ulong = 16;
const SIZEOF_IFREQ: libc::c_ulong = 32;
const SIZEOF_C_UINT: libc::c_ulong = 4;

pub const BIOCSETIF: libc::c_ulong =
    IOC_IN | ((SIZEOF_IFREQ & IOCPARM_MASK) << 16usize) | (('B' as libc::c_ulong) << 8usize) | 108;
pub const BIOCIMMEDIATE: libc::c_ulong =
    IOC_IN | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 112;
pub const BIOCGBLEN: libc::c_ulong =
    IOC_OUT | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 102;
pub const BIOCGDLT: libc::c_ulong =
    IOC_OUT | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 106;

pub const BIOCSBLEN: libc::c_ulong =
    IOC_INOUT | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 102;
pub const BIOCSHDRCMPLT: libc::c_ulong =
    IOC_IN | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 117;
pub const BIOCSRTIMEOUT: libc::c_ulong =
    IOC_IN | ((SIZEOF_TIMEVAL & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 109;

pub const BIOCPROMISC: libc::c_ulong = 
    IOC_NONE | ((0 & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 105;

pub const DLT_NULL: libc::c_uint = 0;

const BPF_ALIGNMENT: libc::c_int = 4;

pub fn BPF_WORDALIGN(x: isize) -> isize {
    let bpf_alignment = BPF_ALIGNMENT as isize;
    (x + (bpf_alignment - 1)) & !(bpf_alignment - 1)
}

#[repr(C)]
pub struct ifreq {
    pub ifr_name: [libc::c_char; IFNAMSIZ],
    pub ifru_addr: libc::sockaddr,
}

#[repr(C)]
pub struct timeval32 {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

#[repr(C)]
pub struct bpf_hdr {
    pub bh_tstamp: timeval32,
    pub bh_caplen: u32,
    pub bh_datalen: u32,
    pub bh_hdrlen: libc::c_ushort,
}

#[cfg(not(windows))]
extern "C" {
    pub fn ioctl(d: libc::c_int, request: libc::c_ulong, ...) -> libc::c_int;
}