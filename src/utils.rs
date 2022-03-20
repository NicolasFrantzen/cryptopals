pub trait UnicodeVectors
{
    fn to_string(&self) -> String;
}

impl UnicodeVectors for [u8]
{
    fn to_string(&self) -> String
    {
        String::from_utf8_lossy(&self).to_string()
    }
}
