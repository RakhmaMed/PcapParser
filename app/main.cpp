#include <iostream>
#include <fstream>
#include <ranges>
#include <chrono>
#include <variant>
#include <algorithm>
#include <unordered_set>

#include <Packet.h>
#include <PcapFileDevice.h>
#include <TcpLayer.h>
#include <HttpLayer.h>
#include <coroutine>

#include "Generator.h"
#include <IPv4Layer.h>
#include <functional>

void analyzePacket(pcpp::RawPacket& rawPacket, std::ofstream& outputFile)
{
    pcpp::Packet parsedPacket(&rawPacket);

    if (parsedPacket.isPacketOfType(pcpp::TCP))
    {
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();

        if (tcpLayer->getTcpHeader()->portDst == htons(554) || tcpLayer->getTcpHeader()->portSrc == htons(554))
        {
            uint8_t* data = tcpLayer->getLayerPayload();
            size_t dataLen = tcpLayer->getLayerPayloadSize();

            outputFile.write(reinterpret_cast<const char*>(data), dataLen);
        }
    }
}

void analyzePackets(std::string inputPath, std::ofstream& outputFile)
{
   auto deleter = [](auto* reader) {
        reader->close();
        delete reader;
        };

    std::unique_ptr<pcpp::IFileReaderDevice, decltype(deleter)> reader{ pcpp::IFileReaderDevice::getReader(inputPath), deleter };

    if (!reader->open())
    {
        std::cerr << "Error opening the pcap file!" << std::endl;
        return;
    }

    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket))
    {
        analyzePacket(rawPacket, outputFile);
    }
}

Generator<pcpp::Packet> generatePackets(std::string inputPath)
{
    auto deleter = [](auto* reader) {
            reader->close();
            delete reader;
        };

    std::unique_ptr<pcpp::IFileReaderDevice, decltype(deleter)> reader{pcpp::IFileReaderDevice::getReader(inputPath), deleter};

    if (!reader->open())
    {
        std::cerr << "Error opening the pcap file!" << std::endl;
        co_return;
    }

    pcpp::RawPacket rawPacket;

    while (reader->getNextPacket(rawPacket))
    {
        pcpp::Packet parsedPacket(&rawPacket);
        co_yield parsedPacket;
    }
}

struct ConnInfo {
    std::string source_ip;
    std::string dest_ip;
    uint16_t    source_port;
    uint16_t    dest_port;

    friend std::ostream& operator<<(std::ostream& oss, const ConnInfo& info) {
        oss << info.source_ip << ':' << info.source_port << " -> " << info.dest_ip << ':' << info.dest_port;
        return oss;
    }

    auto tie() const {
        return std::tie(source_ip, dest_ip, source_port, dest_port);
    }

    bool operator==(const ConnInfo& other) const {
        return tie() == other.tie();
    }
};

struct ConnInfoHash {
    size_t operator()(const ConnInfo& info) const {
        return std::hash<std::string>()(info.source_ip) ^
            std::hash<std::string>()(info.dest_ip) ^
            std::hash<uint16_t>()(info.source_port) ^
            std::hash<uint16_t>()(info.dest_port);
    }
};

int main(int argc, char* argv[])
{
    std::string inputPath = R"(C:\Users\irahm\Downloads\export.pcapng)";
    //std::string inputPath = R"(C:\Users\irahm\Documents\evenct_check.pcapng)";
    std::string outputPath = R"(C:\Users\irahm\Documents\output.txt)";

    std::ofstream outputFile(outputPath);
    if (!outputFile.is_open())
    {
        std::cerr << "Error opening the output file!" << std::endl;
        return 0;
    }


    std::unordered_set<ConnInfo, ConnInfoHash> connections;

    for (pcpp::Packet packet : generatePackets(inputPath)) {
        
        pcpp::IPv4Address srcIP = packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
        pcpp::IPv4Address destIP = packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();
        pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
        if (!tcpLayer)
            continue;

        uint16_t destPort = tcpLayer->getTcpHeader()->portDst;
        uint16_t sourcePort = tcpLayer->getTcpHeader()->portSrc;

        ConnInfo info{
            .source_ip = srcIP.toString(),
            .dest_ip = destIP.toString(),
            .source_port = sourcePort,
            .dest_port = destPort,
        };
        connections.insert(info);
    }

    for (auto&& connection : connections) {
        std::cout << connection << '\n';
    }

    return 0;
}
