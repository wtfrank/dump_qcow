use anyhow::*;
use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

#[derive(Default, Debug)]
struct QcowHeader {
    version: u32,
    backing_file: std::string::String,
    cluster_bits: u32,
    size: u64,
    crypt_method: CryptMethod,
    l1_table: Vec<L1Entry>,
    refcount_table_offset: u64,
    nb_snapshots: u32,
    snapshots_offset: u64,

    //v3
    incompatible_features: u64,
    compatible_features: u64,
    autoclear_features: u64,
    refcount_bits: u32,

    extended_l2_entries: bool,
}

impl std::fmt::Display for QcowHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let used_l1 = self
            .l1_table
            .iter()
            .fold(0, |a, b| if b.offset > 0 { a + 1 } else { a });
        write!(f, "version: {}\nbacking_file: {}\ncluster_bits: {}\nsize: {}\nl1 table: {}/{} entries used\nsnapshots: {}",
        self.version, self.backing_file, self.cluster_bits, self.size, used_l1, self.l1_table.len(), self.nb_snapshots)
    }
}

#[derive(Debug)]
struct L1Entry {
    offset: u64,
    refcount1: bool,
}

#[derive(Default, Debug)]
enum CryptMethod {
    #[default]
    Unencrypted,
    Aes,
    Luks,
}

fn seek_save<T, F>(reader: &mut T, f: &mut F) -> anyhow::Result<()>
where
    T: Seek + Read,
    F: FnMut(&mut T) -> anyhow::Result<()>,
{
    let at = reader.stream_position()?;
    let r = f(reader);
    reader.seek(SeekFrom::Start(at))?;
    r
}

fn load_header(buf: &mut BufReader<File>) -> anyhow::Result<QcowHeader> {
    let mut header: QcowHeader = QcowHeader::default();
    let mut magic: Vec<u8> = vec![0_u8; 4];
    buf.read_exact(&mut magic)?;

    let expected_magic = vec![b'Q', b'F', b'I', 0xfb];

    if magic != expected_magic {
        return Err(anyhow!("Not a qcow file"));
    }

    header.version = buf.read_u32::<BigEndian>()?;
    if header.version < 2 || header.version > 3 {
        return Err(anyhow!("Unhandled qcow version"));
    }

    let backing_file_offset = buf.read_u64::<BigEndian>()?;
    if backing_file_offset == 0 {
        return Err(anyhow!("Only support qcow with backing files"));
    }
    let backing_file_size = buf.read_u32::<BigEndian>()?;
    match backing_file_size {
        0 => return Err(anyhow!("Only support qcow with backing files")),
        backing_file_size if backing_file_size > 1023 => {
            return Err(anyhow!("Invalid backing file name length"))
        }
        _ => (),
    };

    seek_save(buf, &mut |b| {
        b.seek(SeekFrom::Start(backing_file_offset))?;
        let mut buf2: Vec<u8> = vec![0_u8; backing_file_size as usize];
        b.read_exact(&mut buf2[0..(backing_file_size as usize)])?;
        header.backing_file = String::from_utf8(buf2)?;
        Ok(())
    })?;

    header.cluster_bits = buf.read_u32::<BigEndian>()?;
    if header.cluster_bits < 9 {
        return Err(anyhow!("Cluster size is too small"));
    }

    header.size = buf.read_u64::<BigEndian>()?;

    let cm = buf.read_u32::<BigEndian>()?;
    if cm != 0 {
        return Err(anyhow!("Encryption is not supported"));
    }
    header.crypt_method = CryptMethod::Unencrypted;

    let l1_size = buf.read_u32::<BigEndian>()?;
    let l1_offset = buf.read_u64::<BigEndian>()?;
    seek_save(buf, &mut |b| {
        b.seek(SeekFrom::Start(l1_offset))?;
        for _ in (l1_offset..(l1_offset + l1_size as u64)).step_by(8) {
            let entry = b.read_u64::<BigEndian>()?;
            let refcount1 = entry & (1 << 63) != 0;
            let offset = (entry >> 9) & 0x3fff_ffff_ffff;
            header.l1_table.push(L1Entry { offset, refcount1 });
        }
        Ok(())
    })?;

    header.refcount_table_offset = buf.read_u64::<BigEndian>()?;
    header.nb_snapshots = buf.read_u32::<BigEndian>()?;
    header.snapshots_offset = buf.read_u64::<BigEndian>()?;

    if header.version >= 3 {
        load_v3_header(&mut header, buf)?;
    } else {
        header.refcount_bits = 16;
    }

    load_header_extensions(&mut header, buf)?;

    Ok(header)
}

/* loads v3 fields and advances buf to the end of the v3 headers */
fn load_v3_header(header: &mut QcowHeader, buf: &mut BufReader<File>) -> anyhow::Result<()> {
    header.incompatible_features = buf.read_u64::<BigEndian>()?;
    check_incompatible_features(header)?;

    // we can ignore compatible/autoclear features
    header.compatible_features = buf.read_u64::<BigEndian>()?;
    header.autoclear_features = buf.read_u64::<BigEndian>()?;

    let refcount_order = buf.read_u32::<BigEndian>()?;
    if refcount_order > 6 {
        return Err(anyhow!("Invalid refcount order"));
    }
    header.refcount_bits = 1 << refcount_order;

    let header_length = buf.read_u32::<BigEndian>()?;
    //ignore compression
    let at = buf.stream_position()?;
    buf.seek_relative((at - header_length as u64).try_into().unwrap())?;

    Ok(())
}

fn check_incompatible_features(header: &mut QcowHeader) -> anyhow::Result<()> {
    //dirty bit - don't care about refcounts
    if (header.incompatible_features & 0x1) != 0 {}
    //corrupt bit
    if (header.incompatible_features & 0x2) != 0 {
        return Err(anyhow!("will not load corrupt qcow file"));
    }
    //external data file
    if (header.incompatible_features & 0x4) != 0 {
        return Err(anyhow!("cannot handle external data files"));
    }
    //compression type bit
    if (header.incompatible_features & 0x8) != 0 {
        return Err(anyhow!("cannot handle compression"));
    }
    if (header.incompatible_features & 0x10) != 0 {
        header.extended_l2_entries = true;
        return Err(anyhow!("cannot handle extended l2 entries"));
    }
    if (header.incompatible_features & 0xffffffffffffffe0) != 0 {
        return Err(anyhow!("unhandled incompatible feature"));
    }

    Ok(())
}

#[derive(Debug)]
enum HeaderExtension {
    EndOfExtensions,
    BackingFileFormat,
    FeatureNameTable,
    BitmapsExtension,
    FullDiskEncryptionHeader,
    ExternalDataFilename,
    Unknown,
}

fn load_header_extensions(
    _header: &mut QcowHeader,
    buf: &mut BufReader<File>,
) -> anyhow::Result<()> {
    loop {
        let extension_type_data = buf.read_u32::<BigEndian>()?;
        let extension_type = match extension_type_data {
            0x00000000 => HeaderExtension::EndOfExtensions,
            0xe2792aca => HeaderExtension::BackingFileFormat,
            0x6803f857 => HeaderExtension::FeatureNameTable,
            0x23852875 => HeaderExtension::BitmapsExtension,
            0x0537be77 => HeaderExtension::FullDiskEncryptionHeader,
            0x44415441 => HeaderExtension::ExternalDataFilename,
            _ => HeaderExtension::Unknown,
        };

        let length = buf.read_u32::<BigEndian>()?;
        if length > 0 {
            println!("extension header {extension_type:?} {extension_type_data} length {length}");
            let mut buf2 = vec![0_u8; length as usize];
            //buf.read_exact(&mut buf2[0..(length as usize)])?;
            buf.seek_relative(length as i64)?;

            let rem = length % 8;
            if rem > 0 {
                buf.seek_relative((8 - rem).into())?;
            }
        }

        match extension_type {
            HeaderExtension::EndOfExtensions => {
                println!("end of extensions");
                break;
            }
            _ => {
                println!("extension header {extension_type:?}");
            }
        };
    }

    Ok(())
}

pub fn dump(path: std::path::PathBuf) -> anyhow::Result<()> {
    println!("dumping {}", path.display());
    let file = File::open(path)?;
    let mut buf = BufReader::new(file);
    let header = load_header(&mut buf)?;

    println!("{header}");

    Ok(())
}
