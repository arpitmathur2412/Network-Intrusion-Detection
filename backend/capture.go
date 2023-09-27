package main

import (
    // ... Import statements ...
	"fmt"
	"log"
	"time"
	"math"
	"os"
	"encoding/csv"
    "os/signal"
	"syscall"
    "strconv"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

func main() {
    // Define the network interface to capture packets from
    interfaceName := "wlp0s20f3"

    // Open the network interface for packet capture
    handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
    if err != nil {
        log.Fatalf("Error opening interface %s: %v", interfaceName, err)
    }
    defer handle.Close()

	// Create a CSV file for output
	csvFile, err := os.Create("./data/packet_output.csv")
	if err != nil {
		log.Fatalf("Error creating CSV file: %v", err)
	}
	defer csvFile.Close()

	
	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()

	
	header := []string{
        "avg_ipt",
        "bytes_in",
        "bytes_out",
        "dest_ip",
        "dest_port",
        "entropy",
        "proto",
        "source_ip",
        "source_port",
        "time_end",
        "time_start",
        "total_entropy",
    }
	csvWriter.Write(header)

    
	packetCounts := make(map[string]int)
    flowStartTimes := make(map[string]time.Time)
    flowBytesIn := make(map[string]int)
    flowBytesOut := make(map[string]int)
    flowEntropies := make(map[string]float64)
    flowTotalEntropies := make(map[string]float64)
    // lastPacketTime := make(map[string]time.Time)
    // var avgIPT float64

    // Capture packets for 30 seconds
    duration := 5 * time.Second

    sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)


    for{
        select{
            case <- sigCh:
            fmt.Println("Stopping packet capture...")
            return 
        
            default:
                handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
                if err != nil {
                    log.Fatalf("Error opening interface %s: %v", interfaceName, err)
                }
            

                defer handle.Close()
    
                endTime := time.Now().Add(duration)

                packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
                for packet := range packetSource.Packets() {

                    // Check if the capture duration has elapsed
                    if time.Now().After(endTime) {
                        break
                    }

                   

                // Extract relevant packet information
                networkLayer := packet.NetworkLayer()
                transportLayer := packet.TransportLayer()
                applicationLayer := packet.ApplicationLayer()

                count := 0

                if networkLayer != nil && transportLayer != nil {
                    srcIP := "786"
                    dstIP := "786"
                    var protocol int 
                    protocols := transportLayer.LayerType().String()

                    if protocols == "TCP" {
                        protocol = 6
                        
                    } else if protocols == "UDP" {
                        protocol = 17
                        
                    } else {
                        protocol = 1
                    }
                    

                    var srcPort, dstPort int
                    if tcpLayer, ok := transportLayer.(*layers.TCP); ok {
                        srcPort = int(tcpLayer.SrcPort)
                        dstPort = int(tcpLayer.DstPort)
                    } else if udpLayer, ok := transportLayer.(*layers.UDP); ok {
                        srcPort = int(udpLayer.SrcPort)
                        dstPort = int(udpLayer.DstPort)
                    }


                    
                    flowKey := fmt.Sprintf("%s -> %s", srcIP, dstIP)


                    // Ensure that flow data maps are initialized before use
                    if _, exists := packetCounts[flowKey]; !exists {
                        flowStartTimes[flowKey] = time.Now()
                        flowBytesIn[flowKey] = 0
                        flowBytesOut[flowKey] = 0
                        flowEntropies[flowKey] = 0.0
                        flowTotalEntropies[flowKey] = 0.0
                        
                    }

                    currentTime := time.Now()
                    startTimeUnixNano := formatTimeToUnixNano(flowStartTimes[flowKey])

                        endTimeUnixNano := formatTimeToUnixNano(currentTime)
                    // lastTime, exists := lastPacketTime[flowKey]
                    // avgIPT:=0.0

                    // if exists {
                    //     // Calculate the time difference in seconds
                    //     ipt := currentTime.Sub(lastTime).Seconds()
                    //     avgIPT = float64(packetCounts[flowKey]-1) * avgIPT
                        
                    // } 
                    //     avgIPT = 0.0
                    
                    // lastPacketTime[flowKey] = currentTime

                    // Update packet count for the flow
                    if applicationLayer != nil {
                        // Update packet count for the flow
                        packetCounts[flowKey]++
            
                        // Update bytes in and bytes out for the flow
                        
                        
            
                        
                        data := applicationLayer.Payload()
                        entropy := calculateEntropy(data)
                        flowEntropies[flowKey] = entropy
                    


                        
                        row := []string{
                            fmt.Sprintf("%.6f",0.0),
                            fmt.Sprintf("%d", flowBytesIn[flowKey]),
                            fmt.Sprintf("%d", flowBytesOut[flowKey]),
                            fmt.Sprintf("%s", dstIP),
                            fmt.Sprintf("%d", dstPort),
                            fmt.Sprintf("%.2f", flowEntropies[flowKey]),
                            fmt.Sprintf("%d", protocol),
                            fmt.Sprintf("%s", srcIP),
                            fmt.Sprintf("%d", srcPort),
                            startTimeUnixNano,
                            endTimeUnixNano,
                            fmt.Sprintf("%.2f", flowTotalEntropies[flowKey]),
                        }
                        fmt.Println(row)
                        row = row[1:]
                        
                    csvWriter.Write(row)
                    count++
                    

                    // Print flow details
                    // fmt.Printf("Source IP: %s, Destination IP: %s, "+
                    //     "Packet Count: %d, Protocol: %s, "+
                    //     "Bytes In: %d, Bytes Out: %d, "+
                    //     "Entropy (bits/byte): %.2f, Total Entropy: %.2f, "+
                    //     "Start Time: %s\n",
                    //     srcIP, dstIP, packetCounts[flowKey], protocol,
                    //     flowBytesIn[flowKey], flowBytesOut[flowKey],
                    //     entropy, flowTotalEntropies[flowKey],
                    //     flowStartTimes[flowKey].Format("2006-01-02 15:04:05"))
                
                csvWriter.Flush()
                print(count)
                // Sleep for 5 minutes before capturing again
            }
                
                }
                sleepDuration :=1 * time.Second
                    fmt.Printf("Sleeping for %s before capturing again...\n", sleepDuration)
                    time.Sleep(sleepDuration)
            }
        }
    }
}

func formatTimeToUnixNano(t time.Time) string {
    return strconv.FormatInt(t.UnixNano()/1e4, 10)
}

func calculateEntropy(data []byte) float64 {
    if len(data) == 0 {
        return 0.0
    }

    // Calculate entropy using Shannon's entropy formula
    frequency := make(map[byte]float64)
    for _, b := range data {
        frequency[b]++
    }

    entropy := 0.0
    totalBytes := float64(len(data))
    for _, count := range frequency {
        probability := count / totalBytes
        entropy -= probability * math.Log2(probability)
    }

    return entropy
}
