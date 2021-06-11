use std::cmp;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;

use crate::super_block::{
    DataTypes, Features, Field, MemberField, MemberFlag, SuperBlock, SuperBlockFlag,
    SuperBlockFlags, SuperBlockLayout,
};
use crate::{BchError, Result};

use libblkid_rs::BlkidProbe;
use log::{debug, error};
use nix::{ioctl_read, request_code_none};
use uuid::Uuid;

/// The maximum metadata version
const METADATA_VERSION_MAX: u16 = 14;
/// The current metadata version
const METADATA_VERSION_CURRENT: u16 = METADATA_VERSION_MAX - 1;

/// Minumum number of buckets on a device
const MIN_NR_NBUCKETS: u64 = 1 << 6;
/// Smallest supported block size
const MIN_BLOCK_SIZE: u64 = 512;
/// Default supported block size
const DEFAULT_BLOCK_SIZE: u64 = MIN_BLOCK_SIZE;
/// Default btree node size
const DEFAULT_BTREE_NODE_SIZE: u64 = 512;

/// The superblock sector
const SB_SECTOR: u64 = 8;
/// The sector of the default layout
const LAYOUT_SECTOR: u64 = 7;

const BLKPBSZGET_IOC_MAGIC: u8 = 0x12;
const BLKPBSZGET_IOC_TYPE_MODE: u8 = 123;

/// Thin wrapper around ioctl(BLKPBSZGET)
unsafe fn blkpbszget(fd: libc::c_int, data: *mut u64) -> Result<libc::c_int> {
    let res = libc::ioctl(
        fd,
        request_code_none!(BLKPBSZGET_IOC_MAGIC, BLKPBSZGET_IOC_TYPE_MODE),
        data,
    );
    if res != 0 {
        Err(io::Error::from_raw_os_error(res).into())
    } else {
        Ok(res)
    }
}

const BLKGETSIZE64_IOC_MAGIC: u8 = 0x12;
const BLKGETSIZE64_IOC_TYPE_MODE: u8 = 114;

ioctl_read!(
    blkgetsize64,
    BLKGETSIZE64_IOC_MAGIC,
    BLKGETSIZE64_IOC_TYPE_MODE,
    u64
);

/// Arguments that the format subcommand may be provided.
#[derive(Debug)]
pub struct Args {
    /// The number of metadata-replicas to be created
    pub metadata_replicas: u64,
    /// The number of data-replicas to be created
    pub data_replicas: u64,
    /// The formatted device should be encrypted
    pub encrypted: bool,
    /// Do not prompt for a passphrase on creation
    pub no_passphrase: bool,
    /// Do not attempt to initialize the device
    #[allow(dead_code)]
    pub no_initialize: bool,
    /// The disk label
    pub label: Option<String>,
    /// The disk uuid
    pub uuid: Uuid,
    /// Force creation if a preexisting FS exists
    pub force: bool,
    /// The size of the filesystem
    pub superblock_size: u64,
    /// The block size of the new FS
    pub block_size: u16,
    /// The devices to format
    pub devices: Vec<String>,
}

/// Parsed device
#[derive(Debug)]
struct Device {
    dev_name: String,
    size: u64,
    block_size: u64,
    bucket_size: u64,
    nbuckets: u64,
}

impl Device {
    fn file(&self) -> Result<File> {
        Ok(OpenOptions::new().write(true).open(self.dev_name.clone())?)
    }
}

/// The minimum size a device may be given the number of buckets
fn min_size(buckets: u64) -> u64 {
    buckets * MIN_NR_NBUCKETS
}

/// Get the device block size
fn get_blocksize(f: &File) -> Result<u64> {
    let meta = f.metadata()?;
    let ft = meta.file_type();

    if !ft.is_block_device() {
        Ok(meta.st_blksize() >> 9)
    } else {
        let mut data = 0u64;
        unsafe { blkpbszget(f.as_raw_fd(), &mut data)? };
        Ok(data >> 9)
    }
}

/// Get the device size
fn get_size(f: &File) -> Result<u64> {
    let meta = f.metadata()?;
    let ft = meta.file_type();

    if !ft.is_block_device() {
        Ok(meta.st_size())
    } else {
        let mut data = 0u64;
        unsafe { blkgetsize64(f.as_raw_fd(), &mut data)? };
        Ok(data)
    }
}

/// Check if a filesystem exists on the given device
fn check_device(device: &String) -> Result<()> {
    let mut probe = BlkidProbe::new()?;
    let mut input = String::new();

    debug!("openning device: {}", device);
    let f = File::open(device.clone())?;

    let raw_fd = f.as_raw_fd();

    probe.set_device(raw_fd, 0, 0)?;

    probe.enable_partitions(true)?;

    probe.do_fullprobe()?;

    if let Ok(fs_type) = probe.lookup_value("TYPE") {
        if let Ok(fs_label) = probe.lookup_value("LABEL") {
            println!(
                "{} contains a {} FS labelled `{}`",
                device, fs_type, fs_label
            );
        } else {
            println!("{} contains a {} FS", device, fs_type);
        }

        print!("Proceed anyway? ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut input)?;
        let yn = input.trim();

        if yn == "y" || yn == "Y" {
            Ok(())
        } else {
            Err(BchError::Str("Existing filesystem found".to_string()))
        }
    } else {
        Ok(())
    }
}

/// Worker function that formats the given devices per the provided
/// arguments.
fn format(args: Args) -> Result<()> {
    let mut devs = Vec::new();

    for dev in args.devices.iter() {
        let file = OpenOptions::new().write(true).open(dev)?;
        let block_size = get_blocksize(&file)?;
        let size = get_size(&file)? >> 9;

        debug!("device {}: size={} blocksize={}", dev, size, block_size);

        let mut bucket_size = cmp::max(args.block_size as u64, block_size << 9);

        if size < min_size(bucket_size) {
            return Err(BchError::Str(format!(
                "cannot format {}, too small ({} sectors, min {})",
                dev,
                size,
                min_size(DEFAULT_BLOCK_SIZE)
            )));
        }

        bucket_size = cmp::max(bucket_size, MIN_BLOCK_SIZE);

        if size >= min_size(bucket_size) {
            let scale = cmp::max(
                1,
                ((size / min_size(args.block_size as u64)) as f64).log2() as u64 / 4,
            );
            bucket_size = cmp::min(bucket_size * scale, 1 << 11);
        } else {
            while size < min_size(bucket_size) {
                bucket_size /= 2;
            }
        }

        let nbuckets = size / bucket_size;

        if bucket_size < (args.block_size as u64) >> 9 {
            return Err(BchError::Str(format!(
                "{}: block size {} to small for bucket size {}",
                dev, bucket_size, args.block_size
            )));
        }

        if nbuckets < MIN_NR_NBUCKETS {
            return Err(BchError::Str(format!(
                "{}: too few buckets {}",
                dev, nbuckets
            )));
        }

        let device = Device {
            dev_name: dev.clone(),
            block_size,
            size,
            bucket_size,
            nbuckets,
        };
        debug!("parsed device {}: {:?}", dev, device);
        devs.push(device);
    }

    let max_dev_block_size = match devs.iter().map(|dev| dev.block_size).max() {
        Some(blksize) => blksize,
        None => {
            return Err(BchError::Str(
                "could not determine the max device block size".to_string(),
            ));
        }
    };

    debug!("max blocksize={}", max_dev_block_size);

    if u64::from(args.block_size >> 9) < max_dev_block_size {
        return Err(BchError::Str(format!(
            "block size {} too small for max device block size {}",
            args.block_size, max_dev_block_size
        )));
    }

    for (i, dev) in devs.iter().enumerate() {
        let mut file = dev.file()?;

        debug!(
            "zeroing superblock for name={} index={}",
            args.devices[i], i
        );
        const ZEROS: [u8; (SB_SECTOR as usize) << 9] = [0x00; ((SB_SECTOR as usize) << 9)];
        file.write(&ZEROS[..])?;
    }

    let btree_node_size = cmp::min(
        devs.iter()
            .map(|dev| dev.bucket_size)
            .min()
            .unwrap_or(DEFAULT_BTREE_NODE_SIZE),
        DEFAULT_BTREE_NODE_SIZE,
    );

    let mut flags_buf = [0u8; 64];
    let mut flags = SuperBlockFlags::from(&mut flags_buf);

    flags.set_flag(SuperBlockFlag::BTREE_NODE_SIZE, btree_node_size)?;
    flags.set_flag(SuperBlockFlag::GC_RESERVE, 8)?;
    flags.set_flag(SuperBlockFlag::META_REPLICAS_WANT, args.metadata_replicas)?;
    flags.set_flag(SuperBlockFlag::DATA_REPLICAS_WANT, args.data_replicas)?;
    flags.set_flag(SuperBlockFlag::META_REPLICAS_REQ, 1)?;
    flags.set_flag(SuperBlockFlag::DATA_REPLICAS_REQ, 1)?;

    let mut layout_buf = [0u8; 512];
    let mut layout = SuperBlockLayout::from(&mut layout_buf[..]);
    // write out sb layout header
    layout.set_magic()?;
    layout.set_layout_type(0x00)?;
    layout.set_nr_superblocks(0x01)?;
    layout.set_sb_max_size((args.superblock_size as f64).log2() as u8)?;
    // write out one superblock offset
    layout.set_sb_offset(0, SB_SECTOR)?;
    debug!(
        "First superblock at offset={} with sb_size={} block_size={}",
        SB_SECTOR,
        args.superblock_size >> 9,
        args.block_size
    );

    for dev in devs.iter() {
        let mut file = dev.file()?;

        file.seek(SeekFrom::Start(LAYOUT_SECTOR << 9))?;
        file.write(layout.as_ref())?;
    }

    let mut sb_buf = [0u8; 1024];
    let mut sb = SuperBlock::from(&mut sb_buf[..]);

    sb.set_version(METADATA_VERSION_CURRENT)?;
    sb.set_version_min(METADATA_VERSION_CURRENT)?;
    sb.set_magic()?;
    sb.set_block_size(args.block_size >> 9)?;
    sb.set_nr_devices(args.devices.len() as u8)?;

    let uuid = Uuid::new_v4();
    sb.set_uuid(uuid)?;
    sb.set_user_uuid(args.uuid)?;

    if let Some(ref label) = args.label {
        sb.set_label(&label.clone().into_bytes())?;
    }

    debug!(
        "Superblock ID info:\n\tlabel: {}\n\tuuid: {}\n\tuser_uuid: {}",
        args.label.as_ref().unwrap_or(&"(nil)".to_string()),
        uuid,
        args.uuid
    );

    sb.set_time_base_p(1)?;
    sb.set_flags(&flags)?;
    sb.set_layout(&layout)?;

    debug!("Building out features 0x{:x}", Features::ALL);
    sb.set_feature(0, Features::ALL)?;

    let mut member_buf = vec![0u8; 56 * devs.len()];
    for (i, dev) in devs.iter().enumerate() {
        let mut member = MemberField::from(&mut member_buf[(56 * i)..]);
        debug!("building member field for dev: {}", dev.dev_name);

        member.set_uuid(Uuid::new_v4())?;
        member.set_n_buckets(dev.nbuckets)?;
        member.set_first_bucket(0)?;
        member.set_bucket_size(dev.bucket_size as u16)?;

        member.set_flag(MemberFlag::REPLACEMENT, 0)?;
        member.set_flag(MemberFlag::DISCARD, 0)?;
        member.set_flag(MemberFlag::DATA_ALLOWED, DataTypes::DEFAULT.bits())?;
        member.set_flag(MemberFlag::DURABILITY, 2)?;
    }
    sb.add_field(Field::Members, &member_buf)?;

    sb.set_u64s()?;

    for (i, dev) in devs.iter().enumerate() {
        sb.set_dev_idx(i as u8)?;
        sb.set_offset(SB_SECTOR)?;

        let mut file = dev.file()?;
        file.seek(SeekFrom::Start(SB_SECTOR << 9))?;
        file.write(sb.as_ref())?;
    }

    Ok(())
}

/// Real main function for the format subcommand
pub fn format_device(args: Args) {
    if args.encrypted && !args.no_passphrase {
        panic!("No support for encryption yet");
    }

    if !args.force {
        for dev in args.devices.iter() {
            if let Err(e) = check_device(dev) {
                error!("Failed device check: {}", e);
                std::process::exit(1);
            }
        }

        if let Err(e) = format(args) {
            error!("Failed to format devices: {}", e);
            std::process::exit(1);
        }
    }
}
