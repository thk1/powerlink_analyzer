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
extern crate regex;

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
use regex::Regex;

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
	opts.optflag("p", "pgftable", "prints master metrics as pgf table");
	opts.optflag("c", "csv", "prints stats as csv");
	opts.optflag("r", "raw", "prints raw response times as csv");
	opts.optflag("s", "sort", "sort response times (in combination with --raw)");
	opts.optopt("f", "filter", "EXPERT: filter response times (in combination with --raw)", "SQL_WHERE_CLAUSE");

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

	let filter = if matches.opt_present("f") {
		matches.opt_str("f").unwrap()
	} else {
		"type=='pres'".to_string()
	};

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

		if matches.opt_present("p") {
			let filename = file_path.to_str().unwrap();
			let table_name = file_path.file_stem().unwrap().to_str().unwrap();
			let re = Regex::new(r"[0-9_]").unwrap();
			let table_name = re.replace_all(table_name, "");
			eval.print_pgftable(&filename, &table_name);
		} else if matches.opt_present("c") {
			eval.print_stats::<CsvPrinter>();
		} else if matches.opt_present("r") {
			eval.print_raw(&filter, matches.opt_present("s"));
		} else {
			eval.print_metadata::<StdoutPrinter>();
			eval.print_errors::<StdoutPrinter>();
			eval.print_state_changes::<StdoutPrinter>();
			eval.print_stats::<StdoutPrinter>();
		}

	}

}