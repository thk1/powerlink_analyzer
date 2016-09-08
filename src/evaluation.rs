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
use types::*;

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

		if let Some((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter("soc", &"1==1".to_owned()) {
			println!("SoC: min = {}ns max = {}ns avg = {:.0}ns jitter_abs = {}ns jitter_rel = {:.2}%", min,max,avg,jitter_abs,jitter_rel*100.);
		};

		if let Some((min,max,avg,jitter_abs,jitter_rel)) = self.db.get_jitter("response", &format!("type=={}",PacketType::PRes as u8)) {
			println!("PRes response time: min = {}ns max = {}ns avg = {:.0}ns jitter_abs = {}ns jitter_rel = {:.2}%", min,max,avg,jitter_abs,jitter_rel*100.);
		};

	}

}