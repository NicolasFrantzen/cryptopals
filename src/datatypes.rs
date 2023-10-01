#[derive(Debug, PartialEq)]
pub struct Key(pub Vec<u8>);

#[derive(Debug, PartialEq)]
pub struct Cipher(pub Vec<u8>);

#[derive(Debug, PartialEq)]
pub struct Plain(pub Vec<u8>);
