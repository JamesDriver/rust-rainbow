use sha1::Digest;
use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    thread,
    sync::Mutex,
};
use std::sync::Arc;
use rayon;

mod lib;
use crate::lib::{RunTiming, ThreadPool};

const MAX_WORKER: usize = 4;

fn hash_me(line: String) -> String {
    hex::encode(sha1::Sha1::digest(line.as_bytes())) + "," + &line + ","
}

pub fn better_thread_pooling(file_name: &str) -> Result<RunTiming, Box<dyn Error>> {
    let mut timing: RunTiming = RunTiming::default();
    let pool = rayon::ThreadPoolBuilder::new()
    .num_threads(8)
    .build()
    .unwrap();
    let wordlist_file = &File::open(file_name)?;
    let reader = BufReader::new(wordlist_file);
    timing.set_init();
    //let hashes = Vec::new();
    let file = File::create("/usr/local/share/wordlists/SecLists/Passwords/darkweb2017-top10000-test4.txt")?;
    let mut stream = BufWriter::with_capacity(10000,file);
    //let data = Arc::new(Mutex::new(stream));
    pool.install(|| {
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            write!(stream, "{}", (hex::encode(sha1::Sha1::digest(line.as_bytes())) + "," + &line + ","));
        }
    });
    timing.set_complete();
    Ok(timing)
}

pub fn thread_pooling(file_name: &str) -> Result<RunTiming, Box<dyn Error>> {
    let mut timing: RunTiming = RunTiming::default();
    let pool = ThreadPool::new(MAX_WORKER);

    let wordlist_file = &File::open(file_name)?;
    let reader = BufReader::new(wordlist_file);
    timing.set_init();
    //let hashes = Vec::new();
    let file = File::create("/usr/local/share/wordlists/SecLists/Passwords/darkweb2017-top10000-test3.txt")?;
    let stream = BufWriter::with_capacity(10000,file);
    let data = Arc::new(Mutex::new(stream));

    for line in reader.lines() {
        let line = line?;
        let stream = Arc::clone(&data);
        pool.execute(move || {
            let mut stream = stream.lock().unwrap();
            write!(stream, "{}", hash_me(line)).expect("failed to write");
        });
    }

    timing.set_complete();

    Ok(timing)
}

pub fn multi_threaded(file_name: &str) -> Result<RunTiming, Box<dyn Error>> {
    let mut timing: RunTiming = RunTiming::default();
    let wordlist_file = &File::open(file_name)?;
    let reader = BufReader::new(wordlist_file);
    let mut hashes = Vec::new();
    let mut i = 0;
    let mut bufs = vec![Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    timing.set_init();
    let mut file = File::create("/usr/local/share/wordlists/SecLists/Passwords/darkweb2017-top10000-test1.txt")?;

    for line in reader.lines() {
        let line = line?;
        match i {
            1..=2500 => bufs[0].push(line),
            2501..=5000 => bufs[1].push(line),
            5001..=7500 => bufs[2].push(line),
            _ => bufs[3].push(line)
        }
        i+=1;
    }

    for buf in bufs {
        let hash = thread::spawn(move || {
            let mut vec = Vec::new();
            for pass in buf {  
                vec.push(hex::encode(sha1::Sha1::digest(pass.as_bytes())) +","+ &pass +"," )
            }
            vec
        });
        hashes.push(hash);
    }


    for hash_vec in hashes {
        let hashed = hash_vec.join().unwrap();
        write!(file, "{:?}", hashed)?;
    }


    timing.set_complete();

    Ok(timing)
}

pub fn single_threaded(file_name: &str) -> Result<RunTiming, Box<dyn Error>> {
    let mut timing: RunTiming = RunTiming::default();
    let wordlist_file = &File::open(file_name)?;
    let reader = BufReader::new(wordlist_file);
    timing.set_init();

    let mut file = File::create("/usr/local/share/wordlists/SecLists/Passwords/darkweb2017-top10000-test.txt")?;
    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();
        let hashed = hex::encode(sha1::Sha1::digest(common_password.as_bytes()));
        write!(file, "{}\n", hashed)?;
    }
    timing.set_complete();
    Ok(timing)
}

fn percent_faster(a: RunTiming, b: RunTiming) {
    let ac = a.completion-a.initialization;
    let bc = b.completion-b.initialization;
    println!("Option 2 is {} times faster than option 1: {}, {}", (ac/bc), ac, bc)
}


fn main() {
    /*
    Thread pool 12x faster than single threading
    Thread pool 6x faster than multi threading
    */
    println!("hello world");
    let base_single_timing = single_threaded("/usr/local/share/wordlists/SecLists/Passwords/darkweb2017-top10000.txt");
    let base_multi_timing = multi_threaded("/usr/local/share/wordlists/SecLists/Passwords/darkweb2017-top10000.txt");
    let thread_pooling_timing = thread_pooling("/usr/local/share/wordlists/SecLists/Passwords/darkweb2017-top10000.txt");
    let better_thread_pooling = better_thread_pooling("/usr/local/share/wordlists/SecLists/Passwords/darkweb2017-top10000.txt");
    let a = match base_single_timing {
        Ok(t) => t,
        Err(_) => panic!("err"),
    };
    let _b = match base_multi_timing {
        Ok(t) => t,
        Err(_) => panic!("err"),
    };
    let c = match thread_pooling_timing {
        Ok(t) => t,
        Err(_) => panic!("err"),
    };
    let _d = match better_thread_pooling {
        Ok(t) => t,
        Err(_) => panic!("err"),
    };
    //percent_faster(a, b);
    percent_faster(a, _d);
}
