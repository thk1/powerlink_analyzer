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

pub struct Evaluation<'a> {
	db: &'a mut Database,
}

impl<'a> Evaluation<'a> {

	pub fn new(database: &'a mut Database) -> Self {
		Evaluation {
			db: database,
		}
	}

	pub fn print(&self) {

		println!("\nErrors:");
		println!("Notice: Missing Ident Responses from [253] (diagnostic device) and missing responses when CN state is Off are regular.");
		for row in self.db.get_errors() {
			println!("[{:>3}] {:>3}x {:<30} (CN:{:?} MN:{:?})", row.0, row.4, row.1, row.2, row.3);
		}

		println!("\nState Changes:");
		for row in self.db.get_state_changes() {
			println!("{:>5} {:>14}ns [{:>3}] {:?}", Evaluation::group_digits(row.3 as usize),
				Evaluation::group_digits(row.2 as usize), row.0, row.1);
		}


		println!("\nStatistics:");

		if let Ok((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter("soc", "1==1".to_owned()) {
			println_stats!("Cycle/SoC",avg as usize,min as usize,max as usize,jitter_abs as usize,jitter_rel*100.);
		};

		self.print_field("Responses","response","1==1","├─","├─");
		self.print_field("├─PRes","response","type=='pres'","│  ├─","│  └─");
		self.print_field("├─Ident","response","type=='ident'","│  ├─","│  └─");
		self.print_field("├─Status","response","type=='status'","│  ├─","│  └─");
		self.print_field("├─SDO","response","type=='sdo'","│  ├─","│  └─");
		self.print_field("├─NMT","response","type=='nmt_command'","│  ├─","│  └─");
		self.print_field("└─Veth","response","type=='veth'","   ├─","   └─");

	}

	fn print_field(&self, title: &str, table: &str, where_clause: &str, prefix: &str, prefix_end: &str) {
		
		if let Ok((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter(table, where_clause.to_owned()) {
			println_stats!(title,avg as usize,min as usize,max as usize,jitter_abs as usize,jitter_rel*100.);
		};

		let nodes = self.db.get_nodes(table, where_clause.to_owned());

		for (i,node) in nodes.iter().enumerate() {
			if let Ok((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter(table, format!("{} AND node_id=={}",where_clause,node)) {
				let p = if i==nodes.len()-1 {
					prefix_end
				} else {
					prefix
				};
				println_stats!(format!("{}{}",p,node), avg as usize,min as usize,max as usize,jitter_abs as usize,jitter_rel*100.);
			};
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