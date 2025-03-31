use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt; // for .mode() if needed
use std::path::PathBuf;
use std::process;

use nix::unistd::{
    seteuid, setegid, getuid, getgid, Uid, Gid,
};
use nix::unistd::User;
use nix::sys::stat::umask;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SecurityLevel {
    Unclassified,
    Confidential,
    Secret,
    TopSecret,
}

impl SecurityLevel {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "UNCLASSIFIED" => Some(SecurityLevel::Unclassified),
            "CONFIDENTIAL" => Some(SecurityLevel::Confidential),
            "SECRET"       => Some(SecurityLevel::Secret),
            "TOP_SECRET"   => Some(SecurityLevel::TopSecret),
            _ => None,
        }
    }
}

// 사용자의 보안 등급을 mac.policy에서 읽어오기
fn get_user_security_level(username: &str) -> Option<SecurityLevel> {
    let policy_path = PathBuf::from("mac.policy");
    let policy_file = match std::fs::File::open(&policy_path) {
        Ok(f) => f,
        Err(_) => return None, // mac.policy 없으면 None
    };
    let reader = BufReader::new(policy_file);

    for line in reader.lines() {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 && parts[0] == username {
                return SecurityLevel::from_str(parts[1]);
            }
        }
    }
    None
}

// 문서 파일 이름에 따른 보안 등급
fn get_file_security_level(filename: &str) -> Option<SecurityLevel> {
    match filename {
        "unclassified.data" => Some(SecurityLevel::Unclassified),
        "confidential.data" => Some(SecurityLevel::Confidential),
        "secret.data"       => Some(SecurityLevel::Secret),
        "top_secret.data"   => Some(SecurityLevel::TopSecret),
        _ => None, // 과제 조건상, 여길 타지 않아야 함.
    }
}

// read-down : user_level >= file_level
// write-up : user_level <= file_level
fn can_read(user_level: SecurityLevel, file_level: SecurityLevel) -> bool {
    user_level >= file_level
}

fn can_write(user_level: SecurityLevel, file_level: SecurityLevel) -> bool {
    user_level <= file_level
}

// 로그 남기기 (root 권한 drop 후에 수행)
// 요구사항: "<username>.log" 를 0640으로 만들고, 소유주를 해당 사용자로 해야 함.
fn log_command(username: &str, args: &[String]) {
    // 쓰기 내용 자체는 로깅하지 않음 → [ "write", "secret.data", "TEST_INPUT" ]
    // => "write secret.data"
    let log_line = if args.len() >= 2 && args[0] == "write" {
        if args.len() >= 2 {
            format!("write {}\n", args[1])
        } else {
            "write\n".to_string()
        }
    } else {
        // 그냥 join
        args.join(" ") + "\n"
    };

    let log_filename = format!("{}.log", username);

    // umask(0o026) → 새 파일 생성시 0640이 되도록.
    let old_mask = umask(nix::sys::stat::Mode::from_bits_truncate(0o026));

    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_filename)
    {
        Ok(f) => f,
        Err(_) => {
            eprintln!("Failed to open or create log file");
            // umask 원복
            umask(old_mask);
            return;
        }
    };

    // 파일 쓰기
    if let Err(e) = file.write_all(log_line.as_bytes()) {
        eprintln!("Failed to write to log file: {}", e);
    }

    // umask 원복
    umask(old_mask);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("Usage: mac <read|write> <document file> [data]");
        process::exit(1);
    }

    let command = &args[0];
    let filename = &args[1];

    // (1) 현재 effective UID가 root여야 함 (setuid root 실행)
    let ruid = getuid();    
    let rgid = getgid();    
    let euid = nix::unistd::geteuid(); 
    let egid = nix::unistd::getegid(); 

    eprintln!("[INFO] Effective UID = {}, Real UID = {}", euid, ruid);

    if euid.as_raw() != 0 {
        eprintln!("Error: mac must be run as setuid root.");
        process::exit(1);
    }

    // (2) 사용자 이름 찾기
    let user = match User::from_uid(ruid) {
        Ok(Some(u)) => u,
        _ => {
            eprintln!("Error: cannot find real user name!");
            process::exit(1);
        }
    };
    let username = user.name;
    eprintln!("[INFO] Real user = \"{}\"", username);

    // (3) 보안 등급 파악
    let user_level = match get_user_security_level(&username) {
        Some(l) => {
            eprintln!("[INFO] User level = {:?}", l);
            l
        }
        None => {
            eprintln!("[INFO] User not found in policy. ACCESS DENIED");
            println!("ACCESS DENIED");
            process::exit(1);
        }
    };

    let file_level = match get_file_security_level(filename) {
        Some(l) => {
            eprintln!("[INFO] File = \"{}\", File level = {:?}", filename, l);
            l
        }
        None => {
            eprintln!("[INFO] Unknown file. ACCESS DENIED");
            println!("ACCESS DENIED");
            process::exit(1);
        }
    };

    // (4) read or write 로직
    eprintln!("[INFO] Command = {}", command);

    match command.as_str() {
        "read" => {
            let allowed = can_read(user_level, file_level);
            eprintln!(
                "[INFO] Checking read permission: {:?} >= {:?} ? {}",
                user_level, file_level, allowed
            );
            if allowed {
                match fs::read_to_string(filename) {
                    Ok(content) => {
                        print!("{}", content);
                        if !content.ends_with('\n') {
                            print!("\n");
                        }
                    }
                    Err(_) => {
                        eprintln!("[ERROR] Failed to read file");
                        println!("ACCESS DENIED");
                    }
                }
            } else {
                println!("ACCESS DENIED");
            }
        }
        "write" => {
            if args.len() < 3 {
                eprintln!("Usage: mac write <document file> <data>");
                process::exit(1);
            }
            let data_to_write = &args[2];
            let allowed = can_write(user_level, file_level);
            eprintln!(
                "[INFO] Checking write permission: {:?} <= {:?} ? {}",
                user_level, file_level, allowed
            );
            if allowed {
                let mut file = match OpenOptions::new()
                    .append(true)
                    .open(filename)
                {
                    Ok(f) => f,
                    Err(_) => {
                        eprintln!("[ERROR] Failed to open file for writing");
                        println!("ACCESS DENIED");
                        process::exit(1);
                    }
                };
                if let Err(e) = writeln!(file, "{}", data_to_write) {
                    eprintln!("[ERROR] Failed to write to file: {}", e);
                    println!("ACCESS DENIED");
                    process::exit(1);
                } else {
                    eprintln!("[INFO] Appended to file: \"{}\"", data_to_write);
                }
            } else {
                println!("ACCESS DENIED");
            }
        }
        _ => {
            eprintln!("Invalid command: {}", command);
            process::exit(1);
        }
    }

    // (5) 권한 내려놓기
    eprintln!("[INFO] Dropping privileges to UID={}, GID={}", ruid, rgid);
    if let Err(e) = setegid(rgid) {
        eprintln!("Failed to drop group privileges: {}", e);
        process::exit(1);
    }
    if let Err(e) = seteuid(ruid) {
        eprintln!("Failed to drop user privileges: {}", e);
        process::exit(1);
    }

    // (6) 로그 기록
    eprintln!("[INFO] Logging command to {}.log", username);
    log_command(&username, &args);
}
