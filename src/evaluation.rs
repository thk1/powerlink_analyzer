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

//! The Evaluation module is able to pretty print the results using the data from the Database module.

use database::*;

/// Prints a single line in the result table.
macro_rules! println_stats { ( $name:expr, $avg:expr, $min:expr, $max:expr, $jitter_abs:expr, $jitter_rel:expr  ) => ( println!("{:<9} avg = {:>10}ns  min = {:>10}ns  max = {:>10}ns  jitter_abs = {:>9}ns  jitter_rel = {:>6.2}%",
	$name,
	Evaluation::group_digits($avg),
	Evaluation::group_digits($min),
	Evaluation::group_digits($max),
	Evaluation::group_digits($jitter_abs),
	$jitter_rel)
); }

pub trait StatPrinter {
	fn print_stats_header();
	fn print_stats(category: &str, node: Option<u8>, prefix: &str, min: usize, max: usize, avg: usize, jitter_abs: usize, jitter_rel: f64);
}

pub struct StdoutPrinter;
impl StatPrinter for StdoutPrinter {
	
	fn print_stats_header() {
		println!("\nStatistics:");
	}

	fn print_stats(category: &str, node: Option<u8>, prefix: &str, min: usize, max: usize, avg: usize, jitter_abs: usize, jitter_rel: f64) {
		
		if let Some(node) = node {
			println_stats!(&format!("{}{}",prefix,node),avg,min,max,jitter_abs,jitter_rel);
		} else {
			println_stats!(&format!("{}{}",prefix,category),avg,min,max,jitter_abs,jitter_rel);
		}

	}

}

pub struct CsvPrinter;
impl StatPrinter for CsvPrinter {
	
	fn print_stats_header() {
		println!("title,node,min,max,avg,jitter_abs,jitter_rel");
	}

	fn print_stats(category: &str, node: Option<u8>, _: &str, min: usize, max: usize, avg: usize, jitter_abs: usize, jitter_rel: f64) {
		println!("{},{},{},{},{},{},{}",category,node.unwrap_or(0),min,max,avg,jitter_abs,jitter_rel);
	}

}


pub struct Evaluation<'a> {
	db: &'a mut Database,
}

impl<'a> Evaluation<'a> {

	pub fn new(database: &'a mut Database) -> Self {
		Evaluation {
			db: database,
		}
	}

	pub fn print_errors<P: StatPrinter>(&self) {
		println!("\nErrors:");
		println!("Notice: Missing Ident Responses from [253] (diagnostic device) and missing responses when CN state is Off are regular.");
		for row in self.db.get_errors() {
			println!("[{:>3}] {:>3}x {:<30} (CN:{:?} MN:{:?})", row.0, row.4, row.1, row.2, row.3);
		}
	}

	pub fn print_state_changes<P: StatPrinter>(&self) {
		println!("\nState Changes:");
		for row in self.db.get_state_changes() {
			println!("{:>5} {:>14}ns [{:>3}] {:?}", Evaluation::group_digits(row.3 as usize),
				Evaluation::group_digits(row.2 as usize), row.0, row.1);
		}
	}

	pub fn print_stats<P: StatPrinter>(&self) {

		P::print_stats_header();

		if let Ok(stats) = self.db.get_response_stats("soc", "1==1".to_owned()) {
			P::print_stats("Cycle/SoC",None,"",stats.min as usize,stats.max as usize,stats.avg as usize,stats.jitter_abs as usize,stats.jitter_rel*100.);
		};

		self.print_field::<P>("Responses","response","1==1","├─","├─","");
		self.print_field::<P>("PRes","response","type=='pres'","│  ├─","│  └─","├─");
		self.print_field::<P>("Ident","response","type=='ident'","│  ├─","│  └─","├─");
		self.print_field::<P>("Status","response","type=='status'","│  ├─","│  └─","├─");
		self.print_field::<P>("SDO","response","type=='sdo'","│  ├─","│  └─","├─");
		self.print_field::<P>("NMT","response","type=='nmt_command'","│  ├─","│  └─","├─");
		self.print_field::<P>("Veth","response","type=='veth'","   ├─","   └─","└─");

	}

	fn print_field<P: StatPrinter>(&self, title: &str, table: &str, where_clause: &str, prefix: &str, prefix_end: &str, prefix_title: &str) {
		
		if let Ok(stats) = self.db.get_response_stats(table, where_clause.to_owned()) {
			P::print_stats(title,None,prefix_title,stats.min as usize,stats.max as usize,stats.avg as usize,stats.jitter_abs as usize,stats.jitter_rel*100.);
		};

		let nodes = self.db.get_nodes(table, where_clause.to_owned());

		for (i,node) in nodes.iter().enumerate() {
			if let Ok(stats) = self.db.get_response_stats(table, format!("{} AND node_id=={}",where_clause,node)) {
				let p = if i==nodes.len()-1 {
					prefix_end
				} else {
					prefix
				};
				P::print_stats(title,Some(*node),p,stats.min as usize,stats.max as usize,stats.avg as usize,stats.jitter_abs as usize,stats.jitter_rel*100.);
			};
		}

	}

	pub fn print_pgftable(&self, file_name: &str, table_name: &str) {
		println!("% {}", file_name);
		println!("\\pgfplotstableread{{");
		println!("x             y      y-min      y-max");
		if let Ok(stats) = self.db.get_response_stats("response", format!("type=='sdo' AND node_id==240")) {
			println!("sdo   {:>9}  {:>9}  {:>9}", stats.avg as u64, stats.min, stats.max);
		};
		if let Ok(stats) = self.db.get_response_stats("response", format!("type=='nmt_command' AND node_id==240")) {
			println!("nmt   {:>9}  {:>9}  {:>9}", stats.avg as u64, stats.min, stats.max);
		};
		println!("preq  {:>9}  {:>9}  {:>9}", 0u64, 0u64, 0u64);
		println!("}}{{\\tbl{}}}", table_name);
	}

	pub fn print_raw(&self, filter: &str,sort: bool) {
		let rows = self.db.get_raw(filter, sort);
		for row in rows.iter() {
			println!("{},{},{}", row.0, row.1, row.2);
		}
	}

	fn group_digits(n: usize) -> String {
		let string = n.to_string();
		let bytes: Vec<_> = string.bytes().rev().collect();
		let chunks: Vec<_> = bytes.chunks(3).map(|chunk| String::from_utf8_lossy(chunk)).collect();
		let result: Vec<_> = chunks.join("'").bytes().rev().collect();
		String::from_utf8(result).unwrap()
	}

}