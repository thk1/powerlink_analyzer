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

//! The Database module stores latencies together with some metadata.

use rusqlite::Connection;
use time::Duration;
use types::*;
use std::error::Error;
use std::cmp;
use enum_primitive::FromPrimitive;

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
			CREATE TABLE response (
				id              INTEGER PRIMARY KEY,
				type            TEXT NOT NULL,
				node_id         INTEGER NOT NULL,
				timediff_ns     INTEGER NOT NULL,
				cn_state        INTEGER,
				mn_state        INTEGER
			)", &[]).unwrap();

		conn.execute("
			CREATE TABLE errors (
				id              INTEGER PRIMARY KEY,
				type            TEXT NOT NULL,
				node_id         INTEGER NOT NULL,
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

	pub fn insert_response(&self, packet_type: &'static str, node_id: u8, timediff: Duration, mn_state: Option<NmtState>, cn_state: Option<NmtState>) {

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
			INSERT INTO response (type, node_id, timediff_ns, cn_state, mn_state)
			VALUES ($1, $2, $3, $4, $5)",
		&[&packet_type, &(node_id as i64), &(ns as i64), &cn_state_u8, &mn_state_u8]).unwrap();

	}

	pub fn insert_error(&self, packet_type: &'static str, node_id: u8, mn_state: Option<NmtState>, cn_state: Option<NmtState>) {
		
		let cn_state_u8 = match cn_state {
			Some(s) => Some((s as u8) as i64),
			None => None
		};
		
		let mn_state_u8 = match mn_state {
			Some(s) => Some((s as u8) as i64),
			None => None
		};
		
		self.connection.execute("
			INSERT INTO errors (type, node_id, cn_state, mn_state)
			VALUES ($1, $2, $3, $4)",
		&[&packet_type, &(node_id as i64), &cn_state_u8, &mn_state_u8]).unwrap();

	}

	// returns (min,max,avg,jitter_abs,jitter_rel)
	pub fn get_jitter(&self, table: &'static str, where_clause: String) -> Option<(u64,u64,f64,u64,f64)> {

		let res = self.connection.query_row(
				&format!("
					SELECT
						MIN(timediff_ns) as min,
						MAX(timediff_ns) as max,
						AVG(timediff_ns) as avg
					FROM {}
					WHERE {}
				",table,where_clause)[..],
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

	pub fn get_nodes(&self, table: &'static str, where_clause: String) -> Vec<u8> {
		let mut result = Vec::new();
		let mut stmt = self.connection.prepare(&format!("SELECT node_id FROM {} WHERE {} GROUP BY node_id",table,where_clause)[..]).unwrap();
		let node_iter = stmt.query_map(&[], |row| -> u8 {
			row.get::<i32, i64>(0) as u8
		}).unwrap();
		for node in node_iter {
	        result.push(node.unwrap());
	    }
	    return result;
	}

	pub fn get_errors(&self) -> Vec<(u8,String,NmtState,NmtState,usize)> {
		let mut result = Vec::new();
		let mut stmt = self.connection.prepare("SELECT node_id, type, cn_state, mn_state, COUNT(type) FROM errors GROUP BY type,cn_state,mn_state ORDER BY node_id, cn_state, mn_state").unwrap();
		let node_iter = stmt.query_map(&[], |row| -> (i64,String,i64,i64,i64) {
			(row.get(0),row.get(1),row.get_checked(2).unwrap_or(NmtState::Unknown as i64),row.get_checked(3).unwrap_or(NmtState::Unknown as i64),row.get(4))
		}).unwrap();
		for node in node_iter {
			if let Ok(n) = node {
	        	result.push((n.0 as u8, n.1, NmtState::from_u8(n.2 as u8).expect("Invalid NmtState in database!"), NmtState::from_u8(n.3 as u8).expect("Invalid NmtState in database!"), n.4 as usize));
	        };
	    }
	    return result;
	}

}