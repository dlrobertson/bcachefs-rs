use std::ops::Range;

use crate::{BchError, Result};

use bitflags::bitflags;
use byteorder::{ByteOrder, LittleEndian};
use uuid::Uuid;

bitflags! {
    /// Features a superblock may support
    pub struct Features: u64 {
        /// lz4 compression
        const LZ4 = 1 << 0;
        /// gzip compression
        const GZIP = 1 << 1;
        /// zstd compression
        const ZSTD = 1 << 2;
        /// Atomic nlink support
        const ATOMIC_NLINK = 1 << 3;
        /// Error correction? **FIXME**: this may not be right
        const EC = 1 << 4;
        /// Denylist support
        const JOURNAL_SEQ_DENYLIST_V3 = 1 << 5;
        /// Reflink support
        const REFLINK = 1 << 6;
        /// Use the new shortened siphash
        const NEW_SIPHASH = 1 << 7;
        /// Allow inline data
        const INLINE_DATA = 1 << 8;
        /// Allow new extent overwrites
        const NEW_EXTENT_OVERWRITE = 1 << 9;
        /// Incompressible
        const INCOMPRESSIBLE = 1 << 10;
        /// Allow btree v2 pointers
        const BTREE_PTR_V2 = 1 << 11;
        /// Extents above btree updates
        const EXTENTS_ABOVE_BTREE_UPDATES = 1 << 12;
        /// Btree updates are journaled
        const BTREE_UPDATES_JOURNALLED = 1 << 13;
        /// Inline data may be reflinked
        const REFLINK_INLINE_DATA = 1 << 14;
        /// New varint support
        const NEW_VARINT = 1 << 15;
        /// Journal is not flushed
        const JOURNAL_NO_FLUSH = 1 << 16;
        /// Alloc v2 support
        const ALLOC_V2 = 1 << 17;
        /// Extents across btree nodes
        const EXTENTS_ACROSS_BTREE_NODES = 1 << 18;
        /// Features always set from userspace tools
        const ALWAYS = Self::NEW_EXTENT_OVERWRITE.bits |
                       Self::EXTENTS_ABOVE_BTREE_UPDATES.bits |
                       Self::BTREE_UPDATES_JOURNALLED.bits |
                       Self::ALLOC_V2.bits |
                       Self::EXTENTS_ACROSS_BTREE_NODES.bits;
        /// Bitset of all available features
        const ALL = Self::ALWAYS.bits |
                    Self::NEW_SIPHASH.bits |
                    Self::BTREE_PTR_V2.bits |
                    Self::NEW_VARINT.bits |
                    Self::JOURNAL_NO_FLUSH.bits;
    }
}

bitflags! {
    /// The bitmasks for data types
    pub struct DataTypes: u64 {
        /// No data may be stored on this device
        const NONE = 1 << 0;
        /// Superblock data may be stored on this device
        const SB = 1 << 1;
        /// Journal data may be stored on this device
        const JOURNAL = 1 << 2;
        /// Btree pointers may be stored on this device
        const BTREE = 1 << 3;
        /// Extents and reflinks may be stored on this device
        const USER = 1 << 4;
        // NB: The cached and parity data types do not require
        // a device allocator and therefore should not be
        // specified here.
        /// Bitset of the default data types
        const DEFAULT = Self::SB.bits |
                        Self::JOURNAL.bits |
                        Self::BTREE.bits |
                        Self::USER.bits;
    }
}

/// Superblock field types
#[repr(u64)]
pub enum Field {
    /// Journal field
    Journal = 0,
    /// Superblock info on other members of the filesystem
    Members = 1,
    /// Crypt field
    Crypt = 2,
    /// Old Replicas field
    ReplicasV0 = 3,
    /// Quota field
    Quota = 4,
    /// Disk groups field
    DiskGroups = 5,
    /// Clean field
    Clean = 6,
    /// Replicas field
    Replicas = 7,
    /// Journal seq deny list
    JournalSeqDenylist = 8,
}

/// Returns the superblock magic for bcachefs
fn magic() -> Uuid {
    const MAGIC_D4: [u8; 8] = [0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81];
    Uuid::from_fields_le(0xf67385c6, 0x1a4e, 0xca45, &MAGIC_D4)
        .expect("Incorrect Bcachefs Magic specified")
}

mod sb_offsets {
    use super::layout_offsets;
    use std::ops::Range;

    // FIXME: add csum hi/lo from 0..8/8..16
    pub const VERSION: Range<usize> = 16..18;
    pub const VERSION_MIN: Range<usize> = 18..20;
    // reserved four bytes
    pub const MAGIC: Range<usize> = 24..40;
    pub const UUID: Range<usize> = 40..56;
    pub const USER_UUID: Range<usize> = 56..72;
    pub const LABEL: Range<usize> = 72..104;
    pub const LABEL_SIZE: usize = LABEL.end - LABEL.start;
    pub const OFFSET: Range<usize> = 104..112;
    pub const SEQ: Range<usize> = 112..120;
    pub const BLOCK_SIZE: Range<usize> = 120..122;
    pub const DEV_IDX: usize = 122;
    pub const NR_DEVS: usize = 123;
    pub const U64S: Range<usize> = 124..128;
    pub const TIME_BASE_LO: Range<usize> = 128..136;
    pub const TIME_BASE_HI: Range<usize> = 136..140;
    pub const TIME_BASE_P: Range<usize> = 140..144;
    pub const FLAGS: Range<usize> = 144..208;
    pub const FEATURES: Range<usize> = 208..224;
    pub const COMPAT: Range<usize> = 224..240;
    pub const LAYOUT: Range<usize> = 240..(240 + layout_offsets::SB_OFFSET.end);
    pub const FIELDS: usize = LAYOUT.end;
}

mod layout_offsets {
    use std::ops::Range;

    pub const MAGIC: Range<usize> = 0..16;
    pub const LAYOUT_TYPE: usize = 16;
    pub const SB_MAX_SIZE: usize = 17;
    pub const NR_SUPERBLOCKS: usize = 18;
    // 5 bytes of padding
    pub const SB_OFFSET: Range<usize> = 24..512;
}

mod member_offsets {
    use std::ops::Range;

    pub const UUID: Range<usize> = 0..16;
    pub const N_BUCKETS: Range<usize> = 16..24;
    pub const FIRST_BUCKET: Range<usize> = 24..26;
    pub const BUCKET_SIZE: Range<usize> = 26..28;
    // 4 bytes reserved
    pub const FLAGS: Range<usize> = 40..56;
}

/// A superblock
pub struct SuperBlock<T> {
    last_field_offset: usize,
    buffer: T,
}

impl<T> SuperBlock<T> {
    /// Create a superblock view of the given buffer
    pub fn from(buf: T) -> SuperBlock<T> {
        SuperBlock {
            last_field_offset: 0,
            buffer: buf,
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for SuperBlock<T> {
    fn as_ref<'a>(&'a self) -> &'a [u8] {
        self.buffer.as_ref()
    }
}

impl<T: AsRef<[u8]>> SuperBlock<T> {
    /// The current version supported
    pub fn version(&self) -> Result<u16> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::VERSION.end {
            Err(BchError::Exhausted)
        } else {
            Ok(LittleEndian::read_u16(&buf[sb_offsets::VERSION]))
        }
    }

    /// The minimum version supported
    pub fn version_min(&self) -> Result<u16> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::VERSION_MIN.end {
            Err(BchError::Exhausted)
        } else {
            Ok(LittleEndian::read_u16(&buf[sb_offsets::VERSION_MIN]))
        }
    }

    /// The bcachefs identifying magic value
    pub fn magic(&self) -> Result<Uuid> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::MAGIC.end {
            Err(BchError::Exhausted)
        } else {
            let uuid = LittleEndian::read_u128(&buf[sb_offsets::MAGIC]);
            Ok(Uuid::from_u128_le(uuid))
        }
    }

    /// The generated UUID of this superblock
    pub fn uuid(&self) -> Result<Uuid> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::UUID.end {
            Err(BchError::Exhausted)
        } else {
            let uuid = LittleEndian::read_u128(&buf[sb_offsets::UUID]);
            Ok(Uuid::from_u128_le(uuid))
        }
    }

    /// The user set UUID of this superblock
    pub fn user_uuid(&self) -> Result<Uuid> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::USER_UUID.end {
            Err(BchError::Exhausted)
        } else {
            let uuid = LittleEndian::read_u128(&buf[sb_offsets::USER_UUID]);
            Ok(Uuid::from_u128_le(uuid))
        }
    }

    /// The label of this superblock
    pub fn label<'a>(&'a self) -> Result<&'a [u8]> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::LABEL.end {
            Err(BchError::Exhausted)
        } else {
            Ok(&buf[sb_offsets::LABEL])
        }
    }

    /// The block size of this superblock
    pub fn block_size(&self) -> Result<u16> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::BLOCK_SIZE.end {
            Err(BchError::Exhausted)
        } else {
            Ok(LittleEndian::read_u16(&buf[sb_offsets::BLOCK_SIZE]))
        }
    }

    /// The device index of this device
    pub fn device_index(&self) -> Result<u8> {
        let buf = self.buffer.as_ref();
        if buf.len() <= sb_offsets::DEV_IDX {
            Err(BchError::Exhausted)
        } else {
            Ok(buf[sb_offsets::DEV_IDX])
        }
    }

    /// The number of devices
    pub fn nr_devices(&self) -> Result<u8> {
        let buf = self.buffer.as_ref();
        if buf.len() <= sb_offsets::NR_DEVS {
            Err(BchError::Exhausted)
        } else {
            Ok(buf[sb_offsets::NR_DEVS])
        }
    }

    /// The number of u64s in the variable TLV of fields
    pub fn u64s(&self) -> Result<u32> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::U64S.end {
            Err(BchError::Exhausted)
        } else {
            Ok(LittleEndian::read_u32(&buf[sb_offsets::U64S]))
        }
    }

    /// The low bits of the time base
    pub fn time_base_lo(&self) -> Result<u64> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::TIME_BASE_LO.end {
            Err(BchError::Exhausted)
        } else {
            Ok(LittleEndian::read_u64(&buf[sb_offsets::TIME_BASE_LO]))
        }
    }

    /// The high bits of the time base
    pub fn time_base_hi(&self) -> Result<u32> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::TIME_BASE_HI.end {
            Err(BchError::Exhausted)
        } else {
            Ok(LittleEndian::read_u32(&buf[sb_offsets::TIME_BASE_HI]))
        }
    }

    /// The time precision
    pub fn time_base_p(&self) -> Result<u32> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::TIME_BASE_P.end {
            Err(BchError::Exhausted)
        } else {
            Ok(LittleEndian::read_u32(&buf[sb_offsets::TIME_BASE_P]))
        }
    }

    /// The flag u64s
    pub fn flags_u64s(&self) -> Result<[u64; 8]> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::FLAGS.end {
            Err(BchError::Exhausted)
        } else {
            let mut data = [0u64; 8];
            for (i, entry) in buf[sb_offsets::FLAGS].chunks(8).enumerate() {
                data[i] = LittleEndian::read_u64(entry);
            }
            Ok(data)
        }
    }

    /// The feature set at the given index
    pub fn feature(&self, idx: usize) -> Result<u64> {
        let buf = self.buffer.as_ref();
        let start = sb_offsets::FEATURES.start + (idx * 8);
        let range = start..(start + 8);
        if buf.len() < range.end {
            Err(BchError::Exhausted)
        } else {
            Ok(LittleEndian::read_u64(&buf[range]))
        }
    }

    /// Features supported by this superblock
    pub fn features(&self) -> Result<[u64; 2]> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::FEATURES.end {
            Err(BchError::Exhausted)
        } else {
            let mut data = [0u64; 2];
            for (i, entry) in buf[sb_offsets::FEATURES].chunks(8).enumerate() {
                data[i] = LittleEndian::read_u64(entry);
            }
            Ok(data)
        }
    }

    /// Compat features
    pub fn compat(&self) -> Result<[u64; 2]> {
        let buf = self.buffer.as_ref();
        if buf.len() < sb_offsets::COMPAT.end {
            Err(BchError::Exhausted)
        } else {
            let mut data = [0u64; 2];
            for (i, entry) in buf[sb_offsets::COMPAT].chunks(8).enumerate() {
                data[i] = LittleEndian::read_u64(entry);
            }
            Ok(data)
        }
    }
}

impl<T: AsMut<[u8]>> AsMut<[u8]> for SuperBlock<T> {
    fn as_mut<'a>(&'a mut self) -> &'a mut [u8] {
        self.buffer.as_mut()
    }
}

impl<T: AsMut<[u8]>> SuperBlock<T> {
    /// Set the version used
    pub fn set_version(&mut self, version: u16) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::VERSION.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u16(&mut buf[sb_offsets::VERSION], version);
            Ok(())
        }
    }

    /// Set the version minimum
    pub fn set_version_min(&mut self, version: u16) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::VERSION_MIN.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u16(&mut buf[sb_offsets::VERSION_MIN], version);
            Ok(())
        }
    }

    /// Set the bcachefs magic value for this superblock
    pub fn set_magic(&mut self) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::MAGIC.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u128(&mut buf[sb_offsets::MAGIC], magic().to_u128_le());
            Ok(())
        }
    }

    /// Set the generated UUID of this superblock
    pub fn set_uuid(&mut self, uuid: Uuid) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::UUID.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u128(&mut buf[sb_offsets::UUID], uuid.to_u128_le());
            Ok(())
        }
    }

    /// Set the user set UUID of this superblock
    pub fn set_user_uuid(&mut self, uuid: Uuid) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::USER_UUID.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u128(&mut buf[sb_offsets::USER_UUID], uuid.to_u128_le());
            Ok(())
        }
    }

    /// Set the label for this device
    pub fn set_label(&mut self, label: &[u8]) -> Result<()> {
        let buf = self.buffer.as_mut();
        let range = sb_offsets::LABEL.start..(sb_offsets::LABEL.start + label.len());
        if buf.len() < sb_offsets::LABEL.end {
            Err(BchError::Exhausted)
        } else if label.len() > sb_offsets::LABEL_SIZE {
            Err(BchError::Exhausted)
        } else {
            buf[range].copy_from_slice(label);
            Ok(())
        }
    }

    /// Set the sequence number for this superblock
    pub fn set_seq(&mut self, seq: u64) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::SEQ.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u64(&mut buf[sb_offsets::SEQ], seq);
            Ok(())
        }
    }

    /// Set the offset for this superblock
    pub fn set_offset(&mut self, offset: u64) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::OFFSET.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u64(&mut buf[sb_offsets::OFFSET], offset);
            Ok(())
        }
    }

    /// Set the block size for this device
    pub fn set_block_size(&mut self, block_size: u16) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::BLOCK_SIZE.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u16(&mut buf[sb_offsets::BLOCK_SIZE], block_size);
            Ok(())
        }
    }

    /// Set the index of the given device
    pub fn set_dev_idx(&mut self, val: u8) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::DEV_IDX {
            Err(BchError::Exhausted)
        } else {
            buf[sb_offsets::DEV_IDX] = val;
            Ok(())
        }
    }

    /// Set the number of u64s in the variable TLV of fields
    pub fn set_u64s(&mut self) -> Result<()> {
        let buf = self.buffer.as_mut();
        let u64s = (self.last_field_offset / 8) as u32;
        if buf.len() < sb_offsets::DEV_IDX {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u32(&mut buf[sb_offsets::U64S], u64s);
            Ok(())
        }
    }

    /// Set the number of devices
    pub fn set_nr_devices(&mut self, val: u8) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::NR_DEVS {
            Err(BchError::Exhausted)
        } else {
            buf[sb_offsets::NR_DEVS] = val;
            Ok(())
        }
    }

    /// Set the time precision
    pub fn set_time_base_p(&mut self, val: u32) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::TIME_BASE_P.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u32(&mut buf[sb_offsets::TIME_BASE_P], val);
            Ok(())
        }
    }

    /// Set the features bits for the given features index
    pub fn set_feature(&mut self, idx: usize, val: Features) -> Result<()> {
        let buf = self.buffer.as_mut();
        let start = sb_offsets::FEATURES.start + (idx * 8);
        let range = start..(start + 8);
        if buf.len() < range.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u64(&mut buf[range], val.bits());
            Ok(())
        }
    }

    /// Set the superblock flags
    ///
    /// The flags given may be anything that may be a reference to a slice of bytes,
    /// but is likely to be created with `SuperBlockFlags`.
    pub fn set_flags<U: AsRef<[u8]>>(&mut self, flags: U) -> Result<()> {
        let buf = self.buffer.as_mut();
        let flags_buf = flags.as_ref();
        let range = sb_offsets::FLAGS.start..(sb_offsets::FLAGS.start + flags_buf.len());
        if buf.len() < range.end {
            Err(BchError::Exhausted)
        } else {
            buf[range].copy_from_slice(flags_buf);
            Ok(())
        }
    }

    /// Set the superblock layout.
    ///
    /// **NOTE**: This does not set the superblock layout set at the layout sector. Following
    /// the base superblock info but before the variable TLV of fields another copy of the
    /// superblock layout is stored.
    pub fn set_layout<U: AsRef<[u8]>>(&mut self, layout: &SuperBlockLayout<U>) -> Result<()> {
        let buf = self.buffer.as_mut();
        let layout_buf = layout.as_ref();
        let range = sb_offsets::LAYOUT.start..(sb_offsets::LAYOUT.start + layout_buf.len());
        if buf.len() < range.end {
            Err(BchError::Exhausted)
        } else {
            buf[range].copy_from_slice(layout_buf);
            Ok(())
        }
    }

    /// Add a field to the superblock.
    ///
    /// See `Field` for the field types. The field value may be anything that may
    /// be a reference to a slice of bytes, but should have a wrapper view
    /// (e.g. `MemberField`).
    pub fn add_field<U: AsRef<[u8]>>(&mut self, ty: Field, field: U) -> Result<()> {
        let buf = self.buffer.as_mut();
        let field_buf = field.as_ref();
        let field_buf_len = field_buf.len() + 8;
        let start = sb_offsets::FIELDS + self.last_field_offset + 8;
        let range = start..(start + field_buf.len());
        if buf.len() < range.end {
            Err(BchError::Exhausted)
        } else {
            let header_start = sb_offsets::FIELDS + self.last_field_offset;
            let u64s_range = header_start..(header_start + 4);
            let type_range = u64s_range.end..(u64s_range.end + 4);
            LittleEndian::write_u32(&mut buf[u64s_range], (field_buf_len / 8) as u32);
            LittleEndian::write_u32(&mut buf[type_range], ty as u32);
            self.last_field_offset += field_buf_len;
            buf[range].copy_from_slice(field_buf);
            Ok(())
        }
    }
}

/// A superblock layout
pub struct SuperBlockLayout<T> {
    buffer: T,
}

impl<T> SuperBlockLayout<T> {
    /// Create a superblock layout view for the given bytes
    pub fn from(buf: T) -> SuperBlockLayout<T> {
        SuperBlockLayout { buffer: buf }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for SuperBlockLayout<T> {
    fn as_ref<'a>(&'a self) -> &'a [u8] {
        self.buffer.as_ref()
    }
}

impl<T: AsRef<[u8]>> SuperBlockLayout<T> {
    /// Get the magic uuid for the superblock
    pub fn magic(&self) -> Result<Uuid> {
        let buf = self.buffer.as_ref();
        if buf.len() < layout_offsets::MAGIC.end {
            Err(BchError::Exhausted)
        } else {
            let uuid = LittleEndian::read_u128(&buf[layout_offsets::MAGIC]);
            Ok(Uuid::from_u128_le(uuid))
        }
    }

    /// Get the superblock layout type
    pub fn layout_type(&self) -> Result<u8> {
        let buf = self.buffer.as_ref();
        if buf.len() < layout_offsets::LAYOUT_TYPE {
            Err(BchError::Exhausted)
        } else {
            Ok(buf[layout_offsets::LAYOUT_TYPE])
        }
    }

    /// Get the superblock maximum size
    pub fn sb_max_size(&self) -> Result<u8> {
        let buf = self.buffer.as_ref();
        if buf.len() < layout_offsets::SB_MAX_SIZE {
            Err(BchError::Exhausted)
        } else {
            Ok(buf[layout_offsets::SB_MAX_SIZE])
        }
    }

    /// Get the number of encoded superblocks
    pub fn nr_superblocks(&self) -> Result<u8> {
        let buf = self.buffer.as_ref();
        if buf.len() < layout_offsets::NR_SUPERBLOCKS {
            Err(BchError::Exhausted)
        } else {
            Ok(buf[layout_offsets::NR_SUPERBLOCKS])
        }
    }

    /// Get the offset sector for the superblock at the given index
    pub fn sb_offset(&self, idx: usize) -> Result<u64> {
        let buf = self.buffer.as_ref();
        let start = layout_offsets::SB_OFFSET.start + (idx * 8);
        let range = start..(start + 8);
        if buf.len() < range.end {
            Err(BchError::Exhausted)
        } else {
            Ok(LittleEndian::read_u64(&buf[range]))
        }
    }
}

impl<T: AsMut<[u8]>> AsMut<[u8]> for SuperBlockLayout<T> {
    fn as_mut<'a>(&'a mut self) -> &'a mut [u8] {
        self.buffer.as_mut()
    }
}

impl<T: AsMut<[u8]>> SuperBlockLayout<T> {
    /// Set the magic value to the bcachefs magic uuid
    pub fn set_magic(&mut self) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < layout_offsets::MAGIC.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u128(&mut buf[layout_offsets::MAGIC], magic().to_u128_le());
            Ok(())
        }
    }

    /// Set the layout type of the superblock layout
    pub fn set_layout_type(&mut self, val: u8) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < layout_offsets::LAYOUT_TYPE {
            Err(BchError::Exhausted)
        } else {
            buf[layout_offsets::LAYOUT_TYPE] = val;
            Ok(())
        }
    }

    /// Set the superblock max size
    pub fn set_sb_max_size(&mut self, val: u8) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < layout_offsets::SB_MAX_SIZE {
            Err(BchError::Exhausted)
        } else {
            buf[layout_offsets::SB_MAX_SIZE] = val;
            Ok(())
        }
    }

    /// Set the number of superblocks encoded
    pub fn set_nr_superblocks(&mut self, val: u8) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < layout_offsets::NR_SUPERBLOCKS {
            Err(BchError::Exhausted)
        } else {
            buf[layout_offsets::NR_SUPERBLOCKS] = val;
            Ok(())
        }
    }

    /// Set the offset sector for the superblock at the given index
    pub fn set_sb_offset(&mut self, idx: usize, val: u64) -> Result<()> {
        let buf = self.buffer.as_mut();
        let start = layout_offsets::SB_OFFSET.start + (idx * 8);
        let range = start..(start + 8);
        if buf.len() < range.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u64(&mut buf[range], val);
            Ok(())
        }
    }
}

/// A member flag bitmask
pub struct MemberFlag(usize, Range<u64>);

impl MemberFlag {
    /// Bitmask for replacement type for member device
    pub const REPLACEMENT: MemberFlag = MemberFlag(0, 10..14);
    // FIXME: fix this doc
    /// Suspect: may be unused
    pub const DISCARD: MemberFlag = MemberFlag(0, 14..15);
    /// Bitmask for types of data allowed on the member device
    pub const DATA_ALLOWED: MemberFlag = MemberFlag(0, 15..20);
    /// Bitmask for group the member device belongs to
    pub const GROUP: MemberFlag = MemberFlag(0, 20..28);
    /// Bitmask for durrability of the member device
    pub const DURABILITY: MemberFlag = MemberFlag(0, 28..30);
}

/// A member field
pub struct MemberField<T> {
    buffer: T,
}

impl<T> MemberField<T> {
    /// Create a member field view for the given bytes
    pub fn from(buf: T) -> MemberField<T> {
        MemberField { buffer: buf }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for MemberField<T> {
    fn as_ref<'a>(&'a self) -> &'a [u8] {
        self.buffer.as_ref()
    }
}

impl<T: AsMut<[u8]>> AsMut<[u8]> for MemberField<T> {
    fn as_mut<'a>(&'a mut self) -> &'a mut [u8] {
        self.buffer.as_mut()
    }
}

impl<T: AsMut<[u8]>> MemberField<T> {
    /// Set the uuid for this member device
    pub fn set_uuid(&mut self, uuid: Uuid) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < sb_offsets::UUID.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u128(&mut buf[member_offsets::UUID], uuid.to_u128_le());
            Ok(())
        }
    }

    /// Set the number of buckets for this member device
    pub fn set_n_buckets(&mut self, val: u64) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < member_offsets::N_BUCKETS.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u64(&mut buf[member_offsets::N_BUCKETS], val);
            Ok(())
        }
    }

    /// Set the first bucket for this member device
    pub fn set_first_bucket(&mut self, val: u16) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < member_offsets::FIRST_BUCKET.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u16(&mut buf[member_offsets::FIRST_BUCKET], val);
            Ok(())
        }
    }

    /// Set the bucket size for this member device
    pub fn set_bucket_size(&mut self, val: u16) -> Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < member_offsets::BUCKET_SIZE.end {
            Err(BchError::Exhausted)
        } else {
            LittleEndian::write_u16(&mut buf[member_offsets::BUCKET_SIZE], val);
            Ok(())
        }
    }

    /// Set the member flag with the specified value
    pub fn set_flag(&mut self, flag: MemberFlag, val: u64) -> Result<()> {
        let max = (1 << (flag.1.end - flag.1.start)) - 1;

        let buf = self.buffer.as_mut();
        let start = member_offsets::FLAGS.start + (flag.0 * 8) as usize;
        let range = start..(start + 8);

        if buf.len() < range.end || member_offsets::FLAGS.end < range.end {
            Err(BchError::Exhausted)
        } else if val > max {
            Err(BchError::Einval(format!("{} > {}", val, max)))
        } else {
            let mut field = LittleEndian::read_u64(&buf[range.clone()]);
            field &= !(max << flag.1.start);
            field |= val << flag.1.start;
            LittleEndian::write_u64(&mut buf[range], field);
            Ok(())
        }
    }
}

/// A superblock flag bitmask
pub struct SuperBlockFlag(usize, Range<u64>);

impl SuperBlockFlag {
    // index 0
    /// Bitmask for action to take on error
    pub const ERROR_ACTION: SuperBlockFlag = SuperBlockFlag(0, 8..12);
    /// Bitmask for btree node size
    pub const BTREE_NODE_SIZE: SuperBlockFlag = SuperBlockFlag(0, 12..28);
    /// Bitmask for percentage of gc reserve
    pub const GC_RESERVE: SuperBlockFlag = SuperBlockFlag(0, 28..33);
    /// Bitmask for number of metadata replicas wanted
    pub const META_REPLICAS_WANT: SuperBlockFlag = SuperBlockFlag(0, 48..52);
    /// Bitmask for number of data replicas wanted
    pub const DATA_REPLICAS_WANT: SuperBlockFlag = SuperBlockFlag(0, 52..56);
    /// Bitmask for acl flag
    pub const POSIX_ACL: SuperBlockFlag = SuperBlockFlag(0, 56..57);
    /// Bitmask for user quota flag
    pub const USRQUOTA: SuperBlockFlag = SuperBlockFlag(0, 57..58);
    /// Bitmask for group quota flag
    pub const GRPQUOTA: SuperBlockFlag = SuperBlockFlag(0, 57..58);
    /// Bitmask for project quota flag
    pub const PRJQUOTA: SuperBlockFlag = SuperBlockFlag(0, 57..58);
    // index 1
    /// Bitmask for number of metadata replicas required
    pub const META_REPLICAS_REQ: SuperBlockFlag = SuperBlockFlag(1, 20..24);
    /// Bitmask for number of data replicas required
    pub const DATA_REPLICAS_REQ: SuperBlockFlag = SuperBlockFlag(1, 24..28);
    /// Bitmask for the promote target device index
    pub const PROMOTE_TARGET: SuperBlockFlag = SuperBlockFlag(1, 28..40);
    /// Bitmask for the foreground target device index
    pub const FOREGROUND_TARGET: SuperBlockFlag = SuperBlockFlag(1, 40..52);
    /// Bitmask for the background target device index
    pub const BACKGROUND_TARGET: SuperBlockFlag = SuperBlockFlag(1, 52..64);
    // index 2
    /// Bitmask for the background target device index
    pub const METADATA_TARGET: SuperBlockFlag = SuperBlockFlag(3, 16..28);
}

/// A set of superblock flags
pub struct SuperBlockFlags<T> {
    buffer: T,
}

impl<T> SuperBlockFlags<T> {
    /// Create a superblock flag view of the given buffer
    pub fn from(buf: T) -> SuperBlockFlags<T> {
        SuperBlockFlags { buffer: buf }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for SuperBlockFlags<T> {
    fn as_ref<'a>(&'a self) -> &'a [u8] {
        self.buffer.as_ref()
    }
}

impl<T: AsMut<[u8]>> AsMut<[u8]> for SuperBlockFlags<T> {
    fn as_mut<'a>(&'a mut self) -> &'a mut [u8] {
        self.buffer.as_mut()
    }
}

impl<T: AsMut<[u8]>> SuperBlockFlags<T> {
    /// Set the given superblock flag with the given value
    pub fn set_flag(&mut self, flag: SuperBlockFlag, val: u64) -> Result<()> {
        let max = (1 << (flag.1.end - flag.1.start)) - 1;

        let buf = self.buffer.as_mut();
        let start = (flag.0 * 8) as usize;
        let range = start..(start + 8);

        if buf.len() < range.end {
            Err(BchError::Exhausted)
        } else if val > max {
            Err(BchError::Einval(format!("{} > {}", val, max)))
        } else {
            let mut field = LittleEndian::read_u64(&buf[range.clone()]);
            field &= !(max << flag.1.start);
            field |= val << flag.1.start;
            LittleEndian::write_u64(&mut buf[range], field);
            Ok(())
        }
    }
}

#[cfg(test)]
mod test_sb {
    use super::*;
    const EXAMPLE: [u8; 240] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // csum
        0x34, 0x12, // version
        0x56, 0x34, // version min
        0x00, 0x00, 0x00, 0x00, // pad 4 bytes
        0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca, 0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d,
        0x81, // magic
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // uuid
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // user uuid
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // label
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // seq
        0x03, 0x00, // block size
        0x04, // dev index
        0x05, // nr devices
        0x06, 0x00, 0x00, 0x00, // u64s
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // time base lo
        0x00, 0x00, 0x00, 0x00, // time base hi
        0x00, 0x00, 0x00, 0x00, // time base p
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, // flags
        0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // features
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // compat
    ];

    #[test]
    fn parse_simple() {
        let sb = SuperBlock::from(&EXAMPLE);
        assert_eq!(sb.version().unwrap(), 0x1234);
        assert_eq!(sb.version_min().unwrap(), 0x3456);
        assert_eq!(sb.magic().unwrap(), magic());
        assert_eq!(sb.uuid().unwrap(), Uuid::from_u128_le(0));
        assert_eq!(sb.user_uuid().unwrap(), Uuid::from_u128_le(0));
        assert_eq!(*sb.label().unwrap().iter().max().unwrap(), 0);
        assert_eq!(sb.block_size().unwrap(), 3);
        assert_eq!(sb.flags_u64s().unwrap(), [7, 8, 9, 10, 11, 12, 13, 14]);
        assert_eq!(sb.features().unwrap(), [15, 16]);
        assert_eq!(sb.compat().unwrap(), [17, 18]);
    }

    #[test]
    fn build_simple() {
        let mut data = [0x00; 244];
        let mut sb = SuperBlock::from(&mut data);
        sb.set_version(0x1234).unwrap();
        sb.set_version_min(0x3456).unwrap();
        sb.set_magic().unwrap();
        assert_eq!(sb.magic().unwrap(), magic());
        assert_eq!(
            data[..super::sb_offsets::MAGIC.end],
            EXAMPLE[..super::sb_offsets::MAGIC.end]
        );
    }
}

#[cfg(test)]
mod test_layout {
    use super::*;

    const EXAMPLE: [u8; 40] = [
        0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca, 0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d,
        0x81, // magic
        0x00, // layout type
        0x0b, // superblock size
        0x02, // nr superblocks
        0x00, 0x00, 0x00, 0x00, 0x00, // padding
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset #1
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset #2
    ];

    #[test]
    fn parse_simple() {
        let layout = SuperBlockLayout::from(&EXAMPLE);
        assert_eq!(layout.magic().unwrap(), magic());
        assert_eq!(layout.layout_type().unwrap(), 0);
        assert_eq!(layout.sb_max_size().unwrap(), 0x0b);
        assert_eq!(layout.nr_superblocks().unwrap(), 0x02);
        assert_eq!(layout.sb_offset(0).unwrap(), 0x08);
        assert_eq!(layout.sb_offset(1).unwrap(), 0x08);
    }

    #[test]
    fn build_simple() {
        let mut data = [0x00; 40];
        let mut layout = SuperBlockLayout::from(&mut data);
        layout.set_magic().unwrap();
        layout.set_layout_type(0x00).unwrap();
        layout.set_sb_max_size(0x0b).unwrap();
        layout.set_nr_superblocks(0x02).unwrap();
        layout.set_sb_offset(0, 8).unwrap();
        layout.set_sb_offset(1, 8).unwrap();
        assert_eq!(layout.magic().unwrap(), magic());
        assert_eq!(data, EXAMPLE);
    }
}
