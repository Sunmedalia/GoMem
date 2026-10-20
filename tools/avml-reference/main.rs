mod image;
mod io {
    pub mod counter { include!("counter.rs"); }
    pub mod snappy { include!("snappy.rs"); }
}
use std::{env, fs::File, io::{BufWriter, Seek, Write}};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 { return Err("encode|decode INPUT OUTPUT".into()); }
    let input = File::open(&args[2])?;
    let size = input.metadata()?.len();
    let output = BufWriter::new(File::create_new(&args[3])?);
    match args[1].as_str() {
        "encode" => {
            let mut converter = image::Image::from_streams(image::Format::AvmlCompressed, input, output);
            converter.copy_block(0..size)?;
            converter.dst.flush()?;
        },
        "decode" => {
            let mut converter = image::Image::from_streams(image::Format::Lime, input, output);
            while converter.src.stream_position()? < size { converter.convert_block()?; }
            converter.dst.flush()?;
        },
        _ => return Err("unsupported operation".into())
    }
    Ok(())
}
