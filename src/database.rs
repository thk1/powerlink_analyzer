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

use rusqlite::Connection;
use time::Duration;
use types::*;
use std::error::Error;
use std::cmp;

pub struct Database {
	connection: Connection,
}

impl Database {

	pub fn new() -> Self {
		let conn = Connection::open_in_memory().unwrap();

		conn.execute("
			CREATE TABLE soc (
				id              INTEGER PRIMARY KEY,
				timediff_ns     INTEGER NOT NULL,
				mn_state        INTEGER
			)", &[]).unwrap();

		conn.execute("
			CREATE TABLE pres (
				id              INTEGER PRIMARY KEY,
				node_id         INTEGER NOT NULL,
				timediff_ns     INTEGER NOT NULL,
				cn_state        INTEGER,
				mn_state        INTEGER
			)", &[]).unwrap();

		conn.execute("
			CREATE TABLE ident (
				id              INTEGER PRIMARY KEY,
				node_id         INTEGER NOT NULL,
				timediff_ns     INTEGER NOT NULL,
				cn_state        INTEGER,
				mn_state        INTEGER
			)", &[]).unwrap();

		conn.execute("
			CREATE TABLE status (
				id              INTEGER PRIMARY KEY,
				node_id         INTEGER NOT NULL,
				timediff_ns     INTEGER NOT NULL,
				cn_state        INTEGER,
				mn_state        INTEGER
			)", &[]).unwrap();

		conn.execute("
			CREATE TABLE sdo (
				id              INTEGER PRIMARY KEY,
				node_id         INTEGER NOT NULL,
				timediff_ns     INTEGER NOT NULL,
				cn_state        INTEGER,
				mn_state        INTEGER
			)", &[]).unwrap();

		conn.execute("
			CREATE TABLE other (
				id              INTEGER PRIMARY KEY,
				node_id         INTEGER NOT NULL,
				timediff_ns     INTEGER NOT NULL,
				cn_state        INTEGER,
				mn_state        INTEGER
			)", &[]).unwrap();

		return Database { connection: conn }
	}

	pub fn insert_soc(&self, timediff: Duration, mn_state: Option<NmtState>) {
		trace!("Insert SoC");
		let ns = timediff.num_nanoseconds().expect("Timediff is too large to represent it as nanoseconds. Timediffs this lare probably mean an error.");
		let state = match mn_state {
			Some(s) => Some((s as u8) as i64),
			None => None
		};

		self.connection.execute("
			INSERT INTO soc (timediff_ns, mn_state)
			VALUES ($1, $2)",
		&[&(ns as i64), &state]).unwrap();
	}

	pub fn insert_pres(&self, node_id: u8, timediff: Duration, mn_state: Option<NmtState>, cn_state: Option<NmtState>) {

		trace!("Insert PREs");
		let ns = timediff.num_nanoseconds().expect("Timediff is too large to represent it as nanoseconds. Timediffs this lare probably mean an error.");

		let cn_state_u8 = match cn_state {
			Some(s) => Some((s as u8) as i64),
			None => None
		};
		
		let mn_state_u8 = match mn_state {
			Some(s) => Some((s as u8) as i64),
			None => None
		};

		self.connection.execute("
			INSERT INTO pres (node_id, timediff_ns, cn_state, mn_state)
			VALUES ($1, $2, $3, $4)",
		&[&(node_id as i64), &(ns as i64), &cn_state_u8, &mn_state_u8]).unwrap();

	}

	// returns (min,max,avg,jitter_abs,jitter_rel)
	pub fn get_jitter(&self, table: &'static str) -> Option<(u64,u64,f64,u64,f64)> {

		let res = self.connection.query_row(
				&format!("SELECT
					MIN(timediff_ns) as min,
					MAX(timediff_ns) as max,
					AVG(timediff_ns) as avg
				FROM {}",table)[..],
				&[],
				|row| -> (i64,i64,f64) {
					(row.get(0), row.get(1), row.get(2))
	    		}
	    	);

		match res {
			
			Ok((min,max,avg)) => {
				let avg_int = avg as i64;
				let jitter_abs = cmp::max(avg_int-min,max-avg_int);
				let jitter_rel = jitter_abs as f64 / avg;
				
				return Some((min as u64,max as u64,avg,jitter_abs as u64,jitter_rel));
			},

			Err(e) => {
				error!("{:?}",e.description());
				return None;
			}

		}
	}

}