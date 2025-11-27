use std::env;
use std::fs;
use std::io::Read;
use flate2::read::ZlibDecoder;
use sha1::Digest;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("No command provided");
        return;
    }

    match args[1].as_str() {
        "init" => {
            fs::create_dir(".git").ok();
            fs::create_dir(".git/objects").ok();
            fs::create_dir(".git/refs").ok();
            fs::write(".git/HEAD", "ref: refs/heads/main\n").unwrap();
            println!("Initialized git directory");
        }

        "cat-file" => {
            if args.len() < 4 || args[2] != "-p" {
                eprintln!("Usage: cat-file -p <sha>");
                return;
            }
            let sha = &args[3];
            let (dir, file) = sha.split_at(2);
            let path = format!(".git/objects/{}/{}", dir, file);

            let data = fs::read(path).unwrap();
            let mut decoder = ZlibDecoder::new(&data[..]);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).unwrap();

            if let Some(pos) = decompressed.iter().position(|&b| b == 0) {
                let header = &decompressed[..pos];
                let content = &decompressed[pos + 1..];

                let header_str = String::from_utf8_lossy(header);
                let mut parts = header_str.splitn(2, ' ');
                let obj_type = parts.next().unwrap_or("");
                let size_str = parts.next().unwrap_or("");

                let valid_types = ["blob", "tree", "commit", "tag"];
                if !valid_types.contains(&obj_type) {
                    eprintln!("Unknown object type: {}", obj_type);
                    return;
                }

                let size: usize = size_str.parse().unwrap_or(0);
                if size != content.len() {
                    eprintln!(
                        "Size mismatch: header says {}, but data has {} bytes",
                        size,
                        content.len()
                    );
                    return;
                }

                println!("Type: {}", obj_type);
                println!("Size: {}", size);
                println!("Data:\n{}", String::from_utf8_lossy(content));
            } else {
                eprintln!("Invalid git object format: missing header");
            }
        }

        "hash-object" => {
            let write_flag = args.contains(&"-w".to_string());
            let filename = args.last().unwrap();
            let content = fs::read(filename).unwrap();
            let store = [format!("blob {}\0", content.len()).into_bytes(), content].concat();

            let mut hasher = sha1::Sha1::new();
            hasher.update(&store);
            let sha1 = format!("{:x}", hasher.finalize());

            if write_flag {
                let compressed = {
                    use flate2::{write::ZlibEncoder, Compression};
                    use std::io::Write;
                    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
                    enc.write_all(&store).unwrap();
                    enc.finish().unwrap()
                };
                let (dir, file) = sha1.split_at(2);
                fs::create_dir_all(format!(".git/objects/{}", dir)).ok();
                fs::write(format!(".git/objects/{}/{}", dir, file), compressed).unwrap();
            }

            println!("{}", sha1);
        }

        "ls-tree" => {
            if args.len() < 4 || args[2] != "--name-only" {
                eprintln!("Usage: ls-tree --name-only <sha>");
                return;
            }
            let sha = &args[3];
            let (dir, file) = sha.split_at(2);
            let path = format!(".git/objects/{}/{}", dir, file);

            let data = fs::read(path).unwrap();
            let mut decoder = ZlibDecoder::new(&data[..]);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).unwrap();

            let header_end = decompressed.iter().position(|&b| b == 0).unwrap();
            let mut cursor = header_end + 1;

            while cursor < decompressed.len() {
                let mode_start = cursor;
                while decompressed[cursor] != b' ' {
                    cursor += 1;
                }
                let _mode = String::from_utf8_lossy(&decompressed[mode_start..cursor]);
                cursor += 1;

                let name_start = cursor;
                while decompressed[cursor] != 0 {
                    cursor += 1;
                }
                let name = String::from_utf8_lossy(&decompressed[name_start..cursor]);
                cursor += 1;

                cursor += 20;

                println!("{}", name);
            }
        }

        "commit-tree" => {
            if args.len() < 5 {
                eprintln!("Usage: commit-tree <tree_sha> [-p <parent_sha>] -m <message>");
                return;
            }

            let tree_sha = &args[2];
            let mut parent_sha: Option<&str> = None;
            let mut message: Option<String> = None;

            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "-p" => {
                        if i + 1 >= args.len() {
                            eprintln!("Missing value after -p");
                            return;
                        }
                        parent_sha = Some(&args[i + 1]);
                        i += 2;
                    }
                    "-m" => {
                        if i + 1 >= args.len() {
                            eprintln!("Missing value after -m");
                            return;
                        }
                        message = Some(args[i + 1].clone());
                        i += 2;
                    }
                    other => {
                        eprintln!("Unknown option: {}", other);
                        return;
                    }
                }
            }

            let message = match message {
                Some(m) => m,
                None => {
                    eprintln!("Commit message is required (-m <message>)");
                    return;
                }
            };

            let author = "Alexis Gardy <alexisgardy@example.com>";
            let timestamp = 1_600_000_000;
            let timezone = "+0000";

            let mut content = String::new();
            content.push_str(&format!("tree {}\n", tree_sha));
            if let Some(p) = parent_sha {
                content.push_str(&format!("parent {}\n", p));
            }
            content.push_str(&format!(
                "author {} {} {}\n",
                author, timestamp, timezone
            ));
            content.push_str(&format!(
                "committer {} {} {}\n",
                author, timestamp, timezone
            ));
            content.push('\n');
            content.push_str(&message);
            content.push('\n');

            let content_bytes = content.as_bytes();
            let header = format!("commit {}\0", content_bytes.len());
            let store = [header.into_bytes(), content_bytes.to_vec()].concat();

            let mut hasher = sha1::Sha1::new();
            hasher.update(&store);
            let sha1 = format!("{:x}", hasher.finalize());

            {
                use flate2::{write::ZlibEncoder, Compression};
                use std::io::Write;

                let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
                enc.write_all(&store).unwrap();
                let compressed = enc.finish().unwrap();

                let (dir, file) = sha1.split_at(2);
                fs::create_dir_all(format!(".git/objects/{}", dir)).ok();
                fs::write(format!(".git/objects/{}/{}", dir, file), compressed).unwrap();
            }

            println!("{}", sha1);
        }

        "write-tree" => {
            fn hash_and_write_object(data: &[u8]) -> String {
                use flate2::{write::ZlibEncoder, Compression};
                use std::io::Write;

                let mut hasher = sha1::Sha1::new();
                hasher.update(data);
                let sha = format!("{:x}", hasher.finalize());

                let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
                enc.write_all(data).unwrap();
                let compressed = enc.finish().unwrap();

                let (dir, file) = sha.split_at(2);
                fs::create_dir_all(format!(".git/objects/{}", dir)).ok();
                fs::write(format!(".git/objects/{}/{}", dir, file), compressed).unwrap();

                sha
            }

            fn write_tree(dir: &str) -> String {
                let mut entries = Vec::new();

                let mut paths: Vec<_> = fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).collect();
                paths.sort_by_key(|e| e.file_name());

                for entry in paths {
                    let path = entry.path();
                    let name = entry.file_name().into_string().unwrap();
                    if name == ".git" {
                        continue;
                    }

                    if path.is_file() {
                        let content = fs::read(&path).unwrap();
                        let blob_data =
                            [format!("blob {}\0", content.len()).into_bytes(), content].concat();
                        let sha = hash_and_write_object(&blob_data);
                        let raw = hex::decode(&sha).unwrap();

                        entries.extend_from_slice(format!("100644 {}\0", name).as_bytes());
                        entries.extend_from_slice(&raw);
                    } else if path.is_dir() {
                        let sha = write_tree(&path.to_string_lossy());
                        let raw = hex::decode(&sha).unwrap();

                        entries.extend_from_slice(format!("40000 {}\0", name).as_bytes());
                        entries.extend_from_slice(&raw);
                    }
                }

                let tree_data =
                    [format!("tree {}\0", entries.len()).into_bytes(), entries].concat();
                hash_and_write_object(&tree_data)
            }

            let sha = write_tree(".");
            println!("{}", sha);
        }

        "clone" => {
            if args.len() < 4 {
                eprintln!("Usage: clone <url> <directory>");
                return;
            }

            let url = &args[2];
            let dir = &args[3];

            use std::error::Error;

            fn normalize_git_url(url: &str) -> String {
                if url.ends_with(".git") {
                    url.to_string()
                } else {
                    format!("{}.git", url)
                }
            }

            fn pkt_lines(data: &[u8]) -> Vec<Vec<u8>> {
                let mut res = Vec::new();
                let mut i = 0usize;

                while i + 4 <= data.len() {
                    let len_str =
                        std::str::from_utf8(&data[i..i + 4]).unwrap_or("0000");
                    let len = usize::from_str_radix(len_str, 16).unwrap_or(0);
                    i += 4;

                    if len == 0 {
                        continue;
                    }

                    let payload_len = len.saturating_sub(4);
                    if i + payload_len > data.len() {
                        break;
                    }

                    let pkt = data[i..i + payload_len].to_vec();
                    res.push(pkt);
                    i += payload_len;
                }

                res
            }

            fn parse_info_refs(
                data: &[u8],
            ) -> Result<
                (
                    String,
                    String,
                    std::collections::HashMap<String, String>,
                ),
                Box<dyn Error>,
            > {
                use std::collections::HashMap;

                let mut head_sha: Option<String> = None;
                let mut head_target: Option<String> = None;
                let mut refs: HashMap<String, String> = HashMap::new();

                for pkt in pkt_lines(data) {
                    if pkt.starts_with(b"# ") {
                        continue;
                    }
                    if pkt.is_empty() {
                        continue;
                    }

                    let mut parts = pkt.splitn(2, |&b| b == 0);
                    let main = parts.next().unwrap();
                    let caps = parts.next();

                    let line = String::from_utf8_lossy(main).to_string();
                    if line.len() < 41 {
                        continue;
                    }
                    let sha = line[0..40].to_string();
                    let rest = line[41..].to_string();
                    let refname = rest.trim().to_string();

                    if refname == "HEAD" {
                        head_sha = Some(sha);
                        if let Some(c) = caps {
                            let caps_str = String::from_utf8_lossy(c);
                            for cap in caps_str.split(' ') {
                                if let Some(target) = cap.strip_prefix("symref=HEAD:") {
                                    head_target = Some(target.to_string());
                                }
                            }
                        }
                    } else {
                        refs.insert(refname, sha);
                    }
                }

                if head_sha.is_none() {
                    if let Some((k, v)) =
                        refs.iter().find(|(name, _)| name.starts_with("refs/heads/"))
                    {
                        head_sha = Some(v.clone());
                        head_target = Some(k.clone());
                    } else if let Some((k, v)) = refs.iter().next() {
                        head_sha = Some(v.clone());
                        head_target = Some(k.clone());
                    }
                }

                let head_sha = head_sha.ok_or("no refs found in info/refs")?;
                let head_target =
                    head_target.unwrap_or_else(|| "refs/heads/main".to_string());

                Ok((head_sha, head_target, refs))
            }

            fn pkt_line(s: &str) -> Vec<u8> {
                let len = 4 + s.as_bytes().len();
                let mut out = format!("{:04x}", len).into_bytes();
                out.extend_from_slice(s.as_bytes());
                out
            }

            fn write_loose_object(
                git_dir: &str,
                store: &[u8],
            ) -> Result<String, Box<dyn Error>> {
                use flate2::{write::ZlibEncoder, Compression};
                use std::io::Write;

                let mut hasher = sha1::Sha1::new();
                hasher.update(store);
                let sha = format!("{:x}", hasher.finalize());

                let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
                enc.write_all(store)?;
                let compressed = enc.finish()?;

                let (dir, file) = sha.split_at(2);
                let obj_dir = format!("{}/objects/{}", git_dir, dir);
                std::fs::create_dir_all(&obj_dir)?;
                std::fs::write(format!("{}/{}", obj_dir, file), compressed)?;

                Ok(sha)
            }

            fn read_object(
                git_dir: &str,
                sha: &str,
            ) -> Result<(String, Vec<u8>), Box<dyn Error>> {
                let (dir, file) = sha.split_at(2);
                let path = format!("{}/objects/{}/{}", git_dir, dir, file);

                let data = std::fs::read(path)?;
                let mut decoder = ZlibDecoder::new(&data[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;

                let null_pos = decompressed
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or("invalid git object, no header")?;
                let header =
                    String::from_utf8_lossy(&decompressed[..null_pos]).to_string();
                let body = decompressed[null_pos + 1..].to_vec();

                let obj_type = header
                    .split_whitespace()
                    .next()
                    .ok_or("invalid header type")?
                    .to_string();

                Ok((obj_type, body))
            }

            fn checkout_tree(
                git_dir: &str,
                tree_sha: &str,
                workdir: &str,
            ) -> Result<(), Box<dyn Error>> {
                let (obj_type, body) = read_object(git_dir, tree_sha)?;
                if obj_type != "tree" {
                    return Err(format!("expected tree, got {}", obj_type).into());
                }

                let mut i = 0usize;
                while i < body.len() {
                    let mode_start = i;
                    while body[i] != b' ' {
                        i += 1;
                    }
                    let mode = std::str::from_utf8(&body[mode_start..i])?.to_string();
                    i += 1; // espace

                    let name_start = i;
                    while body[i] != 0 {
                        i += 1;
                    }
                    let name =
                        std::str::from_utf8(&body[name_start..i])?.to_string();
                    i += 1; // null

                    let sha_bytes = &body[i..i + 20];
                    i += 20;
                    let child_sha = hex::encode(sha_bytes);

                    if mode.starts_with("40000") {
                        let subdir = format!("{}/{}", workdir, name);
                        std::fs::create_dir_all(&subdir)?;
                        checkout_tree(git_dir, &child_sha, &subdir)?;
                    } else {
                        let (child_type, child_body) =
                            read_object(git_dir, &child_sha)?;
                        if child_type != "blob" {
                            return Err(
                                format!("expected blob, got {}", child_type).into(),
                            );
                        }
                        let path = format!("{}/{}", workdir, name);
                        if let Some(parent) =
                            std::path::Path::new(&path).parent()
                        {
                            std::fs::create_dir_all(parent)?;
                        }
                        std::fs::write(path, child_body)?;
                    }
                }

                Ok(())
            }

            fn parse_pack_and_store(
                git_dir: &str,
                pack: &[u8],
            ) -> Result<(), Box<dyn Error>> {
                if pack.len() < 12 || &pack[0..4] != b"PACK" {
                    return Err("not a PACK file".into());
                }
                let version =
                    u32::from_be_bytes([pack[4], pack[5], pack[6], pack[7]]);
                let num_objects =
                    u32::from_be_bytes([pack[8], pack[9], pack[10], pack[11]]);
                if version != 2 && version != 3 {
                    return Err(format!("unsupported pack version {}", version).into());
                }

                let mut i = 12usize;
                for _ in 0..num_objects {
                    // header varint
                    let first = pack[i];
                    i += 1;
                    let obj_type = (first >> 4) & 0b111;
                    let mut _size = (first & 0b1111) as usize;
                    let mut shift = 4;
                    let mut c = first;

                    while (c & 0x80) != 0 {
                        c = pack[i];
                        i += 1;
                        _size |= ((c & 0x7f) as usize) << shift;
                        shift += 7;
                    }

                    match obj_type {
                        1 | 2 | 3 | 4 => {}
                        6 | 7 => {
                            return Err("delta objects not supported".into());
                        }
                        _ => {
                            return Err(
                                format!("unknown object type {}", obj_type).into(),
                            );
                        }
                    }

                    let cursor = std::io::Cursor::new(&pack[i..]);
                    let mut decoder = ZlibDecoder::new(cursor);
                    let mut out = Vec::new();
                    decoder.read_to_end(&mut out)?;
                    let cursor = decoder.into_inner();
                    let consumed = cursor.position() as usize;
                    i += consumed;

                    let type_str = match obj_type {
                        1 => "commit",
                        2 => "tree",
                        3 => "blob",
                        4 => "tag",
                        _ => unreachable!(),
                    };
                    let header =
                        format!("{} {}\0", type_str, out.len());
                    let store =
                        [header.into_bytes(), out].concat();
                    let _ = write_loose_object(git_dir, &store)?;
                }

                Ok(())
            }

            fn clone_repo(url: &str, dir: &str) -> Result<(), Box<dyn Error>> {
                std::fs::create_dir_all(dir)?;
                let git_dir = format!("{}/.git", dir);
                std::fs::create_dir_all(format!("{}/objects", git_dir))?;
                std::fs::create_dir_all(format!("{}/refs", git_dir))?;

                let base = normalize_git_url(url);
                let info_refs_url =
                    format!("{}/info/refs?service=git-upload-pack", base);
                let upload_pack_url =
                    format!("{}/git-upload-pack", base);

                let client = reqwest::blocking::Client::new();

                let resp = client.get(&info_refs_url).send()?;
                let info_bytes = resp.bytes()?.to_vec();

                let (head_sha, head_target, refs_map) =
                    parse_info_refs(&info_bytes)?;

                let mut body = Vec::new();
                body.extend(pkt_line(&format!("want {}\n", head_sha)));
                body.extend_from_slice(b"0000");
                body.extend(pkt_line("done\n"));

                let resp = client
                    .post(&upload_pack_url)
                    .header(
                        "Content-Type",
                        "application/x-git-upload-pack-request",
                    )
                    .body(body)
                    .send()?;

                let resp_bytes = resp.bytes()?.to_vec();

                let pack_start = resp_bytes
                    .windows(4)
                    .position(|w| w == b"PACK")
                    .ok_or("PACK header not found in response")?;
                let pack = &resp_bytes[pack_start..];

                parse_pack_and_store(&git_dir, pack)?;

                let branch_ref = head_target;
                let branch_sha = refs_map
                    .get(&branch_ref)
                    .unwrap_or(&head_sha);

                let ref_path = format!("{}/{}", git_dir, branch_ref);
                if let Some(parent) =
                    std::path::Path::new(&ref_path).parent()
                {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&ref_path, format!("{}\n", branch_sha))?;
                std::fs::write(
                    format!("{}/HEAD", git_dir),
                    format!("ref: {}\n", branch_ref),
                )?;

                let (commit_type, commit_body) =
                    read_object(&git_dir, branch_sha)?;
                if commit_type != "commit" {
                    return Err("HEAD is not a commit".into());
                }
                let commit_text = String::from_utf8(commit_body)?;
                let tree_line = commit_text
                    .lines()
                    .find(|l| l.starts_with("tree "))
                    .ok_or("no tree line in commit")?;
                let parts: Vec<_> = tree_line.split_whitespace().collect();
                if parts.len() < 2 {
                    return Err("invalid tree line".into());
                }
                let tree_sha = parts[1].to_string();

                checkout_tree(&git_dir, &tree_sha, dir)?;

                Ok(())
            }

            if let Err(e) = clone_repo(url, dir) {
                eprintln!("Error during clone: {}", e);
            }
        }



        _ => {
            eprintln!("Unknown command: {}", args[1]);
        }
    }
}
