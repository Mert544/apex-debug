use std::process::Command;
use std::mem::transmute;

fn run_shell(cmd: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .spawn()
        .unwrap();
}

fn parse_number(s: &str) -> i32 {
    s.parse().unwrap()
}

fn raw_pointer(addr: usize) -> *const i32 {
    unsafe { transmute(addr) }
}

fn main() {
    let x = parse_number("42");
    println!("{}", x);
}
