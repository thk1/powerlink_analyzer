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

use time::Timespec;
use pcap::*;
use types::*;
use num::FromPrimitive;
use database::*;

pub struct Plkan<'a> {
	db: &'a mut Database,
	soc_ts: Option<Timespec>,
	//current_ts: Option<Timespec>,
	current_type: Option<PacketType>,
	current_service: Option<ServiceId>,
	requested_node: Option<u8>,
	mn_state: Option<NmtState>,
}

impl<'a> Plkan<'a> {

	pub fn new(database: &'a mut Database) -> Self {
		Plkan {
			db: database,
			soc_ts: None,
			//current_ts: None,
			current_type: None,
			current_service: None,
			requested_node: None,
			mn_state: None,
		}
	}

	pub fn process_packet(&mut self, packet: &Packet) {
		//info!("timestamp {:?} {:?}", packet.header.ts.tv_sec, packet.header.ts.tv_usec);
		//info!("received packet! {:?}", packet);
		
		// check for non-powerlink traffic
		if self.current_type!=Some(PacketType::ASnd) && self.current_service!=Some(ServiceId::Unspec) && (packet.header.caplen<17 || packet.data[12]!=0x88 || packet.data[13]!=0xab) {
			warn!("Non-powerlink package and VETH not expected: {:?}", packet);
		}

		assert!(packet.header.caplen>16);

		//let dest = packet.data[15];
		//let src = packet.data[16];
		let packet_type = PacketType::from_u8(packet.data[14]);
		info!("Got packet of type {:?}.",packet_type);

		self.process_cyclic(packet);

		self.process_request(packet);
		
		self.reset_expectations();

		self.process_response(packet);
		

	}

	fn process_cyclic(&mut self, packet: &Packet) {

		let packet_type = PacketType::from_u8(packet.data[14]);
		let ts = self.get_timespec(packet);

		if packet_type == Some(PacketType::SoC) {
			if let Some(soc_ts) = self.soc_ts {
				let diff = ts - soc_ts;
				self.db.insert_soc(diff,self.mn_state.clone());
			}
			self.soc_ts = Some(ts);
		}

	}

	fn process_response(&mut self, packet: &Packet) {

		//let dest = packet.data[15];
		let src = packet.data[16];
		let packet_type = PacketType::from_u8(packet.data[14]);

		match self.current_type {
			
			Some(PacketType::PReq) => {
				if packet_type!=Some(PacketType::PRes) || Some(src)!=self.requested_node {
					error!("Missing proper PRes!");
				}
			},

			Some(PacketType::SoA) => {
						
				assert!(packet.header.caplen>17);
				let service = ServiceId::from_u8(packet.data[17]);

				match self.current_service {

					Some(ServiceId::Unspec) => {
						// accept anything
					},

					Some(ServiceId::Ident) => {
						if service!=Some(ServiceId::Ident) || Some(src)!=self.requested_node {
							error!("Missing proper Ident Response!");
						}
					},

					Some(ServiceId::Status) => {
						if service!=Some(ServiceId::Status) || Some(src)!=self.requested_node {
							error!("Missing proper Status Response!");
						}
					},

					_ => {}

				}
			},

			_ => {
				trace!("No expectation.");
			}

		}

	}

	fn process_request(&mut self, packet: &Packet,) {
		
		let dest = packet.data[15];
		//let src = packet.data[16];
		let packet_type = PacketType::from_u8(packet.data[14]);

		match packet_type {
			
			Some(PacketType::PReq) => {
				self.current_type = Some(PacketType::PReq);
				self.requested_node = Some(dest);
			},

			Some(PacketType::SoA) => {
						
				assert!(packet.header.caplen>21);
				let service = ServiceId::from_u8(packet.data[20]);
				let target = packet.data[21];
				
				self.current_type = Some(PacketType::SoA);
				self.current_service = service;
				self.requested_node = Some(target);

			},

			_ => {
				//warn!("Unknown packet.");
			}

		}

	}

	fn reset_expectations(&mut self) {
		self.current_type = None;
		self.current_service = None;
		self.requested_node = None;
	}

	fn get_timespec(&self, packet: &Packet) -> Timespec {
		Timespec {sec: packet.header.ts.tv_sec, nsec: packet.header.ts.tv_usec as i32}
	}

}

