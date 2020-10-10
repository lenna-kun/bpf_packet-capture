extern crate libc;

use super::bpf;

use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem;
use std::ptr;

pub enum Channel {
    Ethernet(DataLinkSender, DataLinkReceiver),
}

/// The BPF-specific configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// The size of buffer to use when writing packets. Defaults to 4096.
    pub write_buffer_size: usize,

    /// The size of buffer to use when reading packets. Defaults to 4096.
    pub read_buffer_size: usize,

    /// The number of /dev/bpf* file descriptors to attempt before failing.
    ///
    /// This setting is only used on OS X - FreeBSD uses a single /dev/bpf rather than creating a
    /// new descriptor each time one is opened.
    ///
    /// Defaults to: 1000.
    pub bpf_fd_attempts: usize,

    pub promiscuous: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            bpf_fd_attempts: 1000,
            promiscuous: true,
        }
    }
}

fn get_fd(attempts: usize) -> libc::c_int {
    for i in 0..attempts {
        let fd = unsafe {
            let file_name = format!("/dev/bpf{}", i);
            libc::open(
                CString::new(file_name.as_bytes()).unwrap().as_ptr(),
                libc::O_RDWR,
                0,
            )
        };
        if fd != -1 {
            return fd;
        }
    }

    -1
}

/// Create a datalink channel using the /dev/bpf device
// NOTE buffer must be word aligned.
pub fn channel(network_interface_name: &String, config: Config) -> io::Result<Channel> {
    let fd = get_fd(config.bpf_fd_attempts);
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut iface: bpf::ifreq = unsafe { mem::zeroed() };
    for (i, c) in network_interface_name.bytes().enumerate() {
        iface.ifr_name[i] = c as i8;
    }

    // NOTE Buffer length must be set before binding to an interface
    //      otherwise this will return Invalid Argument
    if unsafe { bpf::ioctl(fd, bpf::BIOCSBLEN, &(config.read_buffer_size as libc::c_uint)) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // Set the interface to use
    if unsafe { bpf::ioctl(fd, bpf::BIOCSETIF, &iface) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // Return from read as soon as packets are available - don't wait to fill the
    // buffer
    if unsafe { bpf::ioctl(fd, bpf::BIOCIMMEDIATE, &1) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // Get the device type
    let mut dlt: libc::c_uint = 0;
    if unsafe { bpf::ioctl(fd, bpf::BIOCGDLT, &mut dlt) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    if dlt == bpf::DLT_NULL {
        return Err(io::Error::new(io::ErrorKind::Other, "Loopback device is not supported"));
    }

    // Activate promiscuous mode
    if config.promiscuous {
        if unsafe { bpf::ioctl(fd, bpf::BIOCPROMISC, ptr::null::<&libc::c_ulong>()) } == -1 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
    }

    // Enable nonblocking
    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    let sender = DataLinkSender {};

    let mut receiver = DataLinkReceiver {
        fd: fd,
        fd_set: unsafe { mem::zeroed() },
        read_buffer: vec![0; config.read_buffer_size],
        // Enough room for minimally sized packets without reallocating
        packets: VecDeque::with_capacity(config.read_buffer_size / 64),
    };
    unsafe {
        libc::FD_ZERO(&mut receiver.fd_set as *mut libc::fd_set);
        libc::FD_SET(fd, &mut receiver.fd_set as *mut libc::fd_set);
    }

    Ok(Channel::Ethernet(sender, receiver))
}

pub struct DataLinkSender {}

pub struct DataLinkReceiver {
    fd: libc::c_int,
    fd_set: libc::fd_set,
    read_buffer: Vec<u8>,
    packets: VecDeque<(usize, usize)>,
}

impl DataLinkReceiver {
    pub fn next(&mut self) -> io::Result<&[u8]> {
        if self.packets.is_empty() {
            let buffer = &mut self.read_buffer;
            let ret = unsafe {
                libc::FD_SET(self.fd, &mut self.fd_set as *mut libc::fd_set);
                libc::pselect(self.fd + 1, &mut self.fd_set as *mut libc::fd_set, ptr::null_mut(), ptr::null_mut(), ptr::null(), ptr::null(),)
            };
            if ret <= 0 {
                return Err(io::Error::last_os_error());
            }
            let buflen = match unsafe {
                libc::read(
                    self.fd,
                    buffer.as_ptr() as *mut libc::c_void,
                    buffer.len() as libc::size_t,
                )
            } {
                len if len > 0 => len,
                _ => return Err(io::Error::last_os_error()),
            };
            let mut ptr: *mut u8 = buffer.as_mut_ptr();
            let end = unsafe { buffer.as_ptr().offset(buflen as isize) };
            while (ptr as *const u8) < end {
                unsafe {
                    let bpf_packet: *const bpf::bpf_hdr = mem::transmute(ptr);
                    let start = ptr as isize + (*bpf_packet).bh_hdrlen as isize - buffer.as_ptr() as isize;
                    self.packets.push_back((start as usize, (*bpf_packet).bh_caplen as usize));
                    ptr = ptr.offset(bpf::BPF_WORDALIGN((*bpf_packet).bh_hdrlen as isize + (*bpf_packet).bh_caplen as isize));
                }
            }
        }
        let (start, len) = self.packets.pop_front().unwrap();

        Ok(&self.read_buffer[start..start + len])
    }
}