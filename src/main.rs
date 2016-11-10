// Powerlink Analyzer - Analyze Ethernet POWERLINK Network Traffic
// Copyright (C) 2016, Thomas Keh
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! The main module contains initialization tasks and user interaction.

extern crate pcap;
extern crate time;
#[macro_use] extern crate enum_primitive;
extern crate num;
#[macro_use] extern crate log;
extern crate simplelog;
extern crate rusqlite;
extern crate getopts;

mod plkan;
mod types;
mod database;
mod evaluation;

use pcap::*;
use std::path::Path;
use plkan::Plkan;
use database::*;
use evaluation::*;
use getopts::Options;
use std::env;
use simplelog::{SimpleLogger,LogLevelFilter};

fn print_usage(program: &str, opts: Options) {
	let brief = format!("Usage: {} [options] PCAPNG_FILE", program);
	print!("{}", opts.usage(&brief));
}

fn main() {

	let _ = SimpleLogger::init(LogLevelFilter::Info);

	let args: Vec<String> = env::args().collect();
	let program = args[0].clone();

	let mut opts = Options::new();
	opts.optflag("h", "help", "print this help menu");

	let matches = match opts.parse(&args[1..]) {
		Ok(m) => { m }
		Err(f) => { panic!(f.to_string()) }
	};

	if matches.opt_present("h") {
		print_usage(&program, opts);
		return;
	}

	if matches.free.is_empty() {
		error!("No input file given.");
		//warn!("No input file given. Using example capture.");
		//Path::new(concat!(env!("CARGO_MANIFEST_DIR"),"/res/example.pcapng"))
		return;
	}

	for file_path in &matches.free {
		
		//info!("Loading PCAP file {}.",file_path);
		let file_path = Path::new(&file_path);
		let mut cap = Capture::from_file_with_precision(file_path,Precision::Nano).expect("Loading PCAP file failed");
		let mut db = Database::new();
		
		{
			let mut plkan = Plkan::new(&mut db);
			while let Ok(packet) = cap.next() {
				plkan.process_packet(&packet);
			}
		}
		
		let eval = Evaluation::new(&mut db);
		eval.print();
	}

}