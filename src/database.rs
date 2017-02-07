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
use std::cmp;
use enum_primitive::FromPrimitive;
use rusqlite::Error;
use rusqlite::Result;

pub struct Database {
	connection: Connection,
}

pub struct ResponseStats {
	pub min: i64,
	pub max: i64,
	pub avg: f64,
	pub jitter_abs: i64,
	pub jitter_rel: f64,
	pub quartile1: i64,
	pub median: i64,
	pub quartile3: i64
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

		conn.execute("
			CREATE TABLE state_changes (
				id              INTEGER PRIMARY KEY,
				node_id         INTEGER NOT NULL,
				state           INTEGER,
				timestamp       INTEGER NOT NULL,
				packet_id		INTEGER NOT NULL
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

	pub fn insert_response(&self, packet_type: &str, node_id: u8, timediff: Duration, mn_state: Option<NmtState>, cn_state: Option<NmtState>) {

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

	pub fn insert_error(&self, packet_type: &str, node_id: u8, mn_state: Option<NmtState>, cn_state: Option<NmtState>) {
		
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

	pub fn insert_state_change(&self, node_id: u8, state: Option<NmtState>, timestamp: Duration, packet_id: usize) {
		
		let state_i64 = match state {
			Some(s) => Some((s as u8) as i64),
			None => None
		};

		self.connection.execute("
			INSERT INTO state_changes (node_id, state, timestamp, packet_id)
			VALUES ($1, $2, $3, $4)",
		&[&(node_id as i64), &state_i64, &timestamp.num_nanoseconds().unwrap(), &(packet_id as i64)]).unwrap();

	}

	pub fn get_response_stats(&self, table: &str, where_clause: String) -> Result<ResponseStats> {
		
		// note: table and where_clause are not escaed.
		// however we solely work on temporary databases.

		let get_percentile = |percentage: &str| -> Result<i64> {
			
			let mut stmt_percentile = self.connection.prepare(&format!("
						SELECT timediff_ns as percentile,
						FROM {0}
						WHERE {1}
						ORDER BY timediff_ns ASC
						LIMIT 1
						OFFSET (SELECT
								COUNT(*)
								FROM {0}
								WHERE {1})
								* {2} - 1;
					",table,where_clause,percentage)[..]).unwrap();

			let mut query_percentile = stmt_percentile.query(&[])?;
			let row_percentile = query_percentile.next().expect("no database results")?;
			let percentile: i64 = row_percentile.get_checked(0)?;
			Ok(percentile)
		};

		let mut stmt_aggr = self.connection.prepare(&format!("
					SELECT
						MIN(timediff_ns) as min,
						MAX(timediff_ns) as max,
						AVG(timediff_ns) as avg
					FROM {}
					WHERE {}
				",table,where_clause)[..]).unwrap();
		let mut query_aggr = stmt_aggr.query(&[])?;
		let row_aggr = query_aggr.next().expect("no database results")?;
		
		let min: i64 = row_aggr.get_checked(0)?;
		let max: i64 = row_aggr.get_checked(1)?;
		let avg: f64 = row_aggr.get_checked(2)?;
		let avg_int = avg as i64;
		let jitter_abs = cmp::max(avg_int-min,max-avg_int);

		Ok(ResponseStats {
			min: min,
			max: max,
			avg: avg,
			jitter_abs: jitter_abs,
			jitter_rel: jitter_abs as f64 / avg,
			quartile1: get_percentile("1/4")?,
			median: get_percentile("1/2")?,
			quartile3: get_percentile("3/4")?,
		})

		//Ok((min as u64,max as u64,avg,jitter_abs as u64,jitter_rel))

		//} else {
		//	Err(Error::QueryReturnedNoRows)
		//}
		
	}

/*
SELECT
  height AS 'male 90% height'
FROM table
WHERE gender='male'
ORDER BY height ASC
LIMIT 1
OFFSET (SELECT
         COUNT(*)
        FROM table
        WHERE gender='male') * 9 / 10 - 1;
*/


	pub fn get_raw(&self, where_clause: &str, sort: bool) -> Vec<(u64,String,u8)>  {
		let mut result = Vec::new();
		let order = if sort {
			"ORDER BY timediff_ns DESC"
		} else {
			""
		};

		let mut stmt = self.connection.prepare(&format!("
					SELECT
						timediff_ns,
						type,
						node_id
					FROM response
					WHERE {}
					{}
				",where_clause, order)[..]).unwrap();

		let mut rows = stmt.query(&[]).unwrap();
		while let Some(result_row) = rows.next() {
			let row = result_row.unwrap();
			let timediff = row.get::<i32, i64>(0) as u64;
			let packet_type = row.get::<i32, String>(1);
			let node_id = row.get::<i32, i64>(2) as u8;
			result.push((timediff,packet_type,node_id));
		}

		result
	}

	pub fn get_nodes(&self, table: &str, where_clause: String) -> Vec<u8> {
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

	pub fn get_state_changes(&self) -> Vec<(u8,NmtState,i64,i64)> {
		let mut result = Vec::new();
		let mut stmt = self.connection.prepare("SELECT node_id, state, timestamp, packet_id FROM state_changes ORDER BY timestamp").unwrap();
		let node_iter = stmt.query_map(&[], |row| -> (i64,i64,i64,i64) {
			(row.get(0),row.get_checked(1).unwrap_or(NmtState::Unknown as i64),row.get(2),row.get(3))
		}).unwrap();
		for node in node_iter {
			if let Ok(n) = node {
				result.push((n.0 as u8, NmtState::from_u8(n.1 as u8).expect("Invalid NmtState in database!"), n.2, n.3));
			};
		}
		return result;
	}

}