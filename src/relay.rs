use futures::future::join_all;
use futures::future::try_join;
use futures::FutureExt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use tokio;
use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net;
use tokio::net::tcp::{ReadHalf, WriteHalf};

use crate::resolver;
use crate::udp;
use realm::RelayConfig;

extern crate libc;

// Initialize DNS recolver
// Set up channel between listener and resolver

pub async fn start_relay(configs: Vec<RelayConfig>) {
    let default_ip: IpAddr = String::from("0.0.0.0").parse::<IpAddr>().unwrap();
    let remote_addrs: Vec<String> =
        configs.iter().map(|x| x.remote_address.clone()).collect();

    let mut remote_ips: Vec<Arc<RwLock<std::net::IpAddr>>> = Vec::new();
    for _ in 0..remote_addrs.len() {
        remote_ips.push(Arc::new(RwLock::new(default_ip.clone())))
    }
    let cloned_remote_ips = remote_ips.clone();

    tokio::spawn(resolver::resolve(remote_addrs, cloned_remote_ips));

    // resolver::print_ips(&remote_ips);

    let mut iter = configs.into_iter().zip(remote_ips);
    let mut runners = vec![];

    while let Some((config, remote_ip)) = iter.next() {
        runners.push(tokio::spawn(run(config, remote_ip)));
    }

    join_all(runners).await;
}

pub async fn run(config: RelayConfig, remote_ip: Arc<RwLock<IpAddr>>) {
    let client_socket: SocketAddr =
        format!("{}:{}", config.listening_address, config.listening_port)
            .parse()
            .unwrap();
    let tcp_listener = net::TcpListener::bind(&client_socket).await.unwrap();

    let mut remote_socket: SocketAddr =
        format!("{}:{}", remote_ip.read().unwrap(), config.remote_port)
            .parse()
            .unwrap();

    // Start UDP connection
    let udp_remote_ip = remote_ip.clone();
    tokio::spawn(udp::transfer_udp(
        client_socket.clone(),
        remote_socket.port(),
        udp_remote_ip,
    ));

    // Start TCP connection
    loop {
        match tcp_listener.accept().await {
            Ok((inbound, _)) => {
                remote_socket = format!(
                    "{}:{}",
                    &(remote_ip.read().unwrap()),
                    config.remote_port
                )
                .parse()
                .unwrap();
                let transfer = transfer_tcp(inbound, remote_socket.clone())
                    .map(|r| {
                        if let Err(_) = r {
                            return;
                        }
                    });
                tokio::spawn(transfer);
            }
            Err(e) => {
                println!(
                    "TCP forward error {}:{}, {}",
                    config.remote_address, config.remote_port, e
                );
                break;
            }
        }
    }
}

async fn transfer_tcp(
    mut inbound: net::TcpStream,
    remote_socket: SocketAddr,
) -> io::Result<()> {
    let mut outbound = net::TcpStream::connect(remote_socket).await?;
    inbound.set_nodelay(true)?;
    outbound.set_nodelay(true)?;
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = async {
        copy_tcp(&mut ri, &mut wo).await?;
        wo.shutdown().await
    };

    let server_to_client = async {
        copy_tcp(&mut ro, &mut wi).await?;
        wi.shutdown().await
    };

    try_join(client_to_server, server_to_client).await?;

    Ok(())
}

const BUFFERSIZE: usize = if cfg!(not(target_os = "linux")) {
    0x4000 // 16k read/write buffer
} else {
    0x10000 // 64k pipe buffer
};

#[cfg(not(target_os = "linux"))]
async fn copy_tcp(
    r: &mut ReadHalf<'_>,
    w: &mut WriteHalf<'_>,
) -> io::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; BUFFERSIZE];
    let mut n: usize;
    loop {
        n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write(&buf[..n]).await?;
        w.flush().await?;
    }
    Ok(())
}

// zero copy
#[cfg(target_os = "linux")]
async fn copy_tcp(
    r: &mut ReadHalf<'_>,
    w: &mut WriteHalf<'_>,
) -> io::Result<()> {
    use libc::{c_int, O_NONBLOCK};
    use std::os::unix::prelude::AsRawFd;
    // create pipe
    let mut pipes = std::mem::MaybeUninit::<[c_int; 2]>::uninit();
    let (rpipe, wpipe) = unsafe {
        if libc::pipe2(pipes.as_mut_ptr() as *mut c_int, O_NONBLOCK) < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to call pipe",
            ));
        }
        (pipes.assume_init()[0], pipes.assume_init()[1])
    };
    // get raw fd
    let rfd = r.as_ref().as_raw_fd();
    let wfd = w.as_ref().as_raw_fd();
    let mut n: usize = 0;
    let mut done = false;

    'LOOP: loop {
        // read until the socket buffer is empty
        // or the pipe is filled
        r.as_ref().readable().await?;
        while n < BUFFERSIZE {
            match splice_n(rfd, wpipe, BUFFERSIZE - n) {
                x if x > 0 => n += x as usize,
                x if x == 0 => {
                    done = true;
                    break;
                }
                x if x < 0 && is_wouldblock() => break,
                _ => break 'LOOP,
            }
        }
        // write until the pipe is empty
        while n > 0 {
            w.as_ref().writable().await?;
            match splice_n(rpipe, wfd, n) {
                x if x > 0 => n -= x as usize,
                x if x < 0 && is_wouldblock() => {
                    // clear readiness (EPOLLOUT)
                    let _ = r.as_ref().try_write(&[0u8; 0]);
                }
                _ => break 'LOOP,
            }
        }
        // complete
        if done {
            break;
        }
        // clear readiness (EPOLLIN)
        let _ = r.as_ref().try_read(&mut [0u8; 0]);
    }

    unsafe {
        libc::close(rpipe);
        libc::close(wpipe);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn splice_n(r: i32, w: i32, n: usize) -> isize {
    use libc::{loff_t, SPLICE_F_MOVE, SPLICE_F_NONBLOCK};
    unsafe {
        libc::splice(
            r,
            0 as *mut loff_t,
            w,
            0 as *mut loff_t,
            n,
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK,
        )
    }
}

#[cfg(target_os = "linux")]
fn is_wouldblock() -> bool {
    use libc::{EAGAIN, EWOULDBLOCK};
    let errno = unsafe { *libc::__errno_location() };
    errno == EWOULDBLOCK || errno == EAGAIN
}
