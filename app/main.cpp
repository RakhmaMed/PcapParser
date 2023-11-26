#include <iostream>
#include <fstream>
#include <ranges>
#include <chrono>
#include <variant>

#include <Packet.h>
#include <PcapFileDevice.h>
#include <TcpLayer.h>
#include <HttpLayer.h>
#include <coroutine>

#include "Generator.h"

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
    auto start_time = std::chrono::high_resolution_clock::now();
    auto view = generatePackets(inputPath)
        | std::views::filter([](const pcpp::Packet& packet) { return packet.isPacketOfType(pcpp::TCP); })
        | std::views::transform([](const pcpp::Packet& packet) { return packet.getLayerOfType<pcpp::TcpLayer>(); })
        | std::views::filter([](pcpp::TcpLayer * tcpLayer) {return tcpLayer->getTcpHeader()->portDst == htons(554) || tcpLayer->getTcpHeader()->portSrc == htons(554); })
        | std::views::transform([](pcpp::TcpLayer *  tcpLayer) {
                uint8_t* data = tcpLayer->getLayerPayload();
                size_t dataLen = tcpLayer->getLayerPayloadSize();

                return std::string_view{ reinterpret_cast<const char*>(data), dataLen };
            });

    std::ranges::copy(view, std::ostream_iterator<std::string_view>(outputFile));

    //analyzePackets(inputPath, outputFile);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    std::cout << "Time taken: " << duration.count() << " milliseconds" << std::endl;

    return 0;
}
