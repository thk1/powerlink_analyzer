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

impl<'a> Evaluation<'a> {

	pub fn new(database: &'a mut Database) -> Self {
		Evaluation {
			db: database,
		}
	}

	pub fn print(&self) {

		if let Some((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter("soc", "1==1") {
			println!("SoC:    avg = {:>8.0}ns  min = {:>8}ns  max = {:>8}ns  jitter_abs = {:>7}ns  jitter_rel = {:>6.2}%", avg,min,max,jitter_abs,jitter_rel*100.);
		};

		if let Some((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter("response", "type=='pres'") {
			println!("PRes:   avg = {:>8.0}ns  min = {:>8}ns  max = {:>8}ns  jitter_abs = {:>7}ns  jitter_rel = {:>6.2}%", avg,min,max,jitter_abs,jitter_rel*100.);
		};

		if let Some((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter("response", "type=='ident'") {
			println!("Ident:  avg = {:>8.0}ns  min = {:>8}ns  max = {:>8}ns  jitter_abs = {:>7}ns  jitter_rel = {:>6.2}%", avg,min,max,jitter_abs,jitter_rel*100.);
		};

		if let Some((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter("response", "type=='status'") {
			println!("Status: avg = {:>8.0}ns  min = {:>8}ns  max = {:>8}ns  jitter_abs = {:>7}ns  jitter_rel = {:>6.2}%", avg,min,max,jitter_abs,jitter_rel*100.);
		};

	}

}