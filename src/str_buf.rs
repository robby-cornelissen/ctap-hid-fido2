use crate::util;
use pad::PadStr;
use std::fmt::Display;

pub struct StrBuf {
    buf: String,
    pad: usize,
}
impl StrBuf {
    pub fn new(pad_to_width: usize) -> Self {
        StrBuf {
            buf: String::from(""),
            pad: pad_to_width,
        }
    }

    // Add str and return StrBuf
    pub fn add(&mut self, val: &str) -> &mut Self {
        self.buf = self.buf.to_string() + val;
        self
    }

    // Add str + \n and return StrBuf
    pub fn add_line(&mut self, val: &str) -> &mut Self {
        self.buf = format!("{}{}\n", self.buf, val);
        self
    }

    // Create String from title and bytes
    pub fn create_hex(title: &str, bytes: &[u8]) -> String {
        let mut strbuf = StrBuf::new(0);
        strbuf.append_hex(title, bytes).build().to_string()
    }

    pub fn append_title(&mut self, title: &str) -> &mut Self {
        let tmp = format!("{}\n", title);
        self.buf = self.buf.to_string() + &tmp;
        self
    }

    pub fn append<T: Display>(&mut self, title: &str, val: &T) -> &mut Self {
        let tmp = format!("{} = {}\n", title.pad_to_width(self.pad), val);
        self.buf = self.buf.to_string() + &tmp;
        self
    }

    pub fn append_option<T: Display>(&mut self, title: &str, val: &Option<T>) -> &mut Self {
        if val.as_ref().is_some() {
            self.append(title, val.as_ref().unwrap());
        }
        self
    }

    pub fn append_hex(&mut self, title: &str, bytes: &[u8]) -> &mut Self {
        let title2 = format!("{}({:02})", title, bytes.len());
        let tmp = format!(
            "{} = {}\n",
            title2.pad_to_width(self.pad),
            util::to_hex_str(bytes)
        );
        self.buf = self.buf.to_string() + &tmp;
        self
    }

    pub fn build(&self) -> &str {
        &self.buf
    }
}
