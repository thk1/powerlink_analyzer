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

#![allow(dead_code)]

enum_from_primitive! {
	#[derive(Debug, PartialEq, Clone)]
	#[repr(u8)]
	pub enum PacketType {
		SoC = 0x01,
		PReq = 0x03,
		PRes = 0x04,
		SoA = 0x05,
		ASnd = 0x06,
	}
}

enum_from_primitive! {
	#[derive(Debug, PartialEq, Clone)]
	#[repr(u8)]
	pub enum ServiceId {
		Ident = 0x01,
		Status = 0x02,
		Sdo = 0x05,
		Unspec = 0xFF,
	}
}

enum_from_primitive! {
	#[derive(Debug, PartialEq, Clone)]
	#[repr(u8)]
	pub enum NmtState {
		Off = 0x00,
		Initialising = 0x19,
		ResetApplication = 0x29,
		ResetCommunication = 0x39,
		ResetConfiguration = 0x79,
		NotActive = 0x1C,
		PreOperational1 = 0x1D,
		PreOperational2 = 0x5D,
		ReadyToOperate = 0x6D,
		Operational = 0xFD,
		Stopped = 0x4D,
		BasicEthernet = 0x1E,
	}
}

