#include <iostream>
#include "zuu/net.hpp"

using namespace zuu::net ;

inline std::ostream& operator<<(std::ostream& os, const ipv4& address) noexcept {
	for(auto& octet : address) {
		os << static_cast<uint32_t>(octet) << (&octet != (address.end() - 1) ? '.' : '\0') ;
	}
	return os ;
}

int main() {
	auto ip1 = ipv4({192, 168, 1, 50}) ;
	auto subnetmask = CreateSubnetMask(24) ;
	std::cout << "IP Address\t\t: " << ip1 << '\n' ;
	std::cout << "Netword Address\t\t: " << ip1.network_address(subnetmask) << '\n' ;
	std::cout << "Broadcast Address\t: " << ip1.network_address(subnetmask) << '\n' ;
	auto host_range = ip1.host_range(subnetmask) ;
	std::cout << "Host Ranges\t\t: " << host_range.first << " - " << host_range.last << '\n' ;

	return 0 ;
}
