// Powerlink Analyzer - Analyze Ethernet POWERLINK Network Traffic Captures
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

extern crate pcap;
extern crate time;
#[macro_use] extern crate enum_primitive;
extern crate num;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate rusqlite;

mod plkan;
mod types;
mod database;
mod evaluation;

use pcap::*;
use std::path::Path;
use plkan::Plkan;
use database::*;
use evaluation::*;

fn main() {

	env_logger::init().unwrap();

	let example_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("res").join("example.pcapng");
    info!("Ethernet POWERLINK network traffic analyzer");
    info!("Loading PCAP file {}.",example_path.to_str().expect("invalid path"));

    let mut cap = Capture::from_file_with_precision(example_path,Precision::Nano).expect("Loading PCAP file failed");

    let mut db = Database::new();
    
    {
	    let mut plkan = Plkan::new(&mut db);

		while let Ok(packet) = cap.next() {
			plkan.process_packet(&packet);
		}
	}
    
    {
	    let eval = Evaluation::new(&mut db);
		eval.print();
	}

}