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

use database::*;

pub struct Evaluation<'a> {
	db: &'a mut Database,
}
	
	macro_rules! println_stats { ( $name:expr, $avg:expr, $min:expr, $max:expr, $jitter_abs:expr, $jitter_rel:expr  ) => ( println!("{:<9} avg = {:>8.0}ns  min = {:>8}ns  max = {:>8}ns  jitter_abs = {:>7}ns  jitter_rel = {:>6.2}%", $name, $avg, $min, $max, $jitter_abs, $jitter_rel) ); }

impl<'a> Evaluation<'a> {

	pub fn new(database: &'a mut Database) -> Self {
		Evaluation {
			db: database,
		}
	}

	pub fn print(&self) {

		if let Some((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter("soc", "1==1".to_owned()) {
			println_stats!("SoC:",avg,min,max,jitter_abs,jitter_rel*100.);
		};

		self.print_field("Any","response","1==1","├──","├──");
		self.print_field("├─PRes","response","type=='pres'","│  ├─","│  └─");
		self.print_field("├─Ident","response","type=='ident'","│  ├─","│  └─");
		self.print_field("├─Status","response","type=='status'","│  ├─","│  └─");
		self.print_field("├─SDO","response","type=='sdo'","│  ├─","│  └─");
		self.print_field("└─Veth","response","type=='veth'","   ├─","   └─");

	}

	fn print_field(&self, title: &'static str, table: &'static str, where_clause: &'static str, prefix: &'static str, prefix_end: &'static str) {
		
		if let Some((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter(table, where_clause.to_owned()) {
			println_stats!(title,avg,min,max,jitter_abs,jitter_rel*100.);
		};

		let nodes = self.db.get_nodes(table, where_clause.to_owned());

		for (i,node) in nodes.iter().enumerate() {
			if let Some((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter(table, format!("{} AND node_id=={}",where_clause,node)) {
				let p = if i==nodes.len()-1 {
					prefix_end
				} else {
					prefix
				};
				println_stats!(format!("{}{}",p,node), avg,min,max,jitter_abs,jitter_rel*100.);
			};
		}
		
	} 

}