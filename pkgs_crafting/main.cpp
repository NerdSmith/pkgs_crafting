#include <iostream>
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "HttpLayer.h"
#include "DnsLayer.h"

int main() {

	pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("1c:69:7a:ae:ef:e3"), pcpp::MacAddress("aa:bb:cc:dd:ee"));

	pcpp::IPv4Layer newIPLayer(pcpp::IPv4Address("192.168.1.1"), pcpp::IPv4Address("10.0.0.1"));
	newIPLayer.getIPv4Header()->ipId = pcpp::hostToNet16(2000);
	newIPLayer.getIPv4Header()->timeToLive = 64;

	//pcpp::TcpLayer newTcpLayer(12345, 80);
	//newTcpLayer.getTcpHeader()->windowSize = pcpp::hostToNet16(6);
	//newTcpLayer.getTcpHeader()->pshFlag = 1;
	//newTcpLayer.getTcpHeader()->ackFlag = 1;
	//newTcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NOP));
	//newTcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NOP));
	//newTcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NOP));
	//newTcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::PCPP_TCPOPT_TIMESTAMP, (uint16_t)1460));
	//newTcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::EOL));

	//newTcpLayer.addTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::PCPP_TCPOPT_NOP, (uint16_t) 100));


	pcpp::UdpLayer newUdpLayer(12345, 53);

	pcpp::DnsLayer newDnsLayer;
	newDnsLayer.addQuery("www.ebay.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);

 // 	pcpp::HttpRequestLayer httpRequestLayer(
	//	pcpp::HttpRequestLayer::HttpGET, 
	//	"http://www.columbia.edu/~fdc/sample.html", 
	//	pcpp::HttpVersion::OneDotOne
	//);

	//httpRequestLayer.addField(PCPP_HTTP_HOST_FIELD, "www.google.com");
	//httpRequestLayer.addField(PCPP_HTTP_REFERER_FIELD, "www.aol.com");

	//pcpp::HeaderField* xForwardedForField = httpRequestLayer.insertField(httpRequestLayer.getFieldByName(PCPP_HTTP_HOST_FIELD), "X-Forwarded-For", "1.1.1.1");
	//httpRequestLayer.insertField(xForwardedForField, "Cache-Control", "max-age=0");

	pcpp::Packet newPacket(100);

	newPacket.addLayer(&newEthernetLayer);
	newPacket.addLayer(&newIPLayer);
	newPacket.addLayer(&newUdpLayer);
	newPacket.addLayer(&newDnsLayer);

	newPacket.computeCalculateFields();

	pcpp::PcapFileWriterDevice writer2("1_new_packet.pcap");
	writer2.open();
	writer2.writePacket(*(newPacket.getRawPacket()));
	writer2.close();

	return 0;
}