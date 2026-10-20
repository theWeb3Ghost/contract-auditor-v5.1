fn main() {
    let hex_str = "60806040526004361061011d";
    let result = hex::decode(hex_str);
    match result {
        Ok(bytes) => {
            println!("Decoded {} bytes: {:?}", bytes.len(), bytes);
            for (i, b) in bytes.iter().enumerate() {
                println!("  byte[{}]: 0x{:02x}", i, b);
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}
