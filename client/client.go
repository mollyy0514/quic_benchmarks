package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mackerelio/go-osstat/memory"
	"github.com/quic-go/quic-go" // my go extension did this everytime I hit save.
)

const initialMessageSize = 1      // 1 byte
const finalMessageSize = 67108864 // 64 mb
const bufferMaxSize = 1048576     // 1mb
const filesToSend = 10            // Duplicate files to send over the same session, using multi-stream or other techniques if applicable.
const sampleSizes = 5             // The number of times each experiment is executed

var dataBuffer []byte = nil
var httpByteBuffer [][]byte = nil

func getSizeString(size int) string {
	newSize := float64(size)
	unit := "b"
	if size >= 1048576 {
		unit = "mib"
		newSize /= 1048576.0
	} else if size >= 1024 {
		unit = "kib"
		newSize /= 1024.0
	}
	return fmt.Sprintf("%.0f %s", newSize, unit)
}

func report(protocol string, environment string, kind string, filesToSend int, setupDuration time.Duration, firstByteDuration time.Duration, size int,
	duration time.Duration, memoryBefore *memory.Stats, memoryAfter *memory.Stats, cpuBefore *cpu.Stats, cpuAfter *cpu.Stats) {

	fileSizeStr := getSizeString(size)
	goodput := (float64(size) / duration.Seconds()) * float64(filesToSend)

	fmt.Printf("[%s - %s] [%d files] setup: %s, firstbyte: %s, sent: %s, duration: %s (goodput: %.0f kbps)\n", protocol, environment, filesToSend, setupDuration, firstByteDuration, fileSizeStr, duration, goodput/1024.0)

	// if size >= 32 {

	// 	fileName := fmt.Sprintf("/var/log/output/meter_%s.csv", environment)

	// 	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	cpuUser := cpuAfter.User - cpuBefore.User
	// 	cpuSystem := cpuAfter.System - cpuBefore.System
	// 	cpuTotal := cpuAfter.Total - cpuBefore.Total

	// 	memoryDiff := memoryAfter.Used - memoryBefore.Used

	// 	// environment
	// 	f.WriteString(fmt.Sprintf("%s,%s,%s,%d,", protocol, kind, environment, filesToSend))
	// 	f.WriteString(fmt.Sprintf("%d,%d,", setupDuration.Microseconds(), firstByteDuration.Microseconds()))
	// 	f.WriteString(fmt.Sprintf("%s,%d,%f,", fileSizeStr, duration.Microseconds(), goodput))
	// 	f.WriteString(fmt.Sprintf("%d,%d,%d,", cpuUser, cpuSystem, cpuTotal))
	// 	f.WriteString(fmt.Sprintf("%d,%d", int(memoryDiff/1048576.0), int(memoryAfter.Used/1048576.0)))
	// 	f.WriteString("\n")
	// }
}

func main() {
	host := flag.String("host", "127.0.0.1", "Host to connect")
	environment := flag.String("env", "Local", "Environment name")
	quicPort := flag.Int("quic", 4242, "QUIC port to connect")
	flag.Parse()
	// Run the loops a bunch of times
	for i := 0; i < sampleSizes; i++ {

		// Set up random data to send.
		dataBuffer = make([]byte, finalMessageSize)
		rand.Read(dataBuffer)

		size := 1
		i := 0
		for size <= finalMessageSize {
			size *= 2
			i++
		}
		finalIteraction := i

		size = 1
		i = 0
		httpByteBuffer = make([][]byte, finalIteraction)
		for size <= finalMessageSize {
			httpByteBuffer[i] = make([]byte, size)
			rand.Read(httpByteBuffer[i])
			size *= 2
			i++
		}

		fmt.Printf("Starting clients to reach %s...\n", *host)

		// Run QUIC first, early feedback on UDP connections
		if *quicPort > 0 {
			errQuic := clientQuicMain(*environment, *host, *quicPort)
			if errQuic != nil {
				panic(errQuic)
			}
		}
	}
}

func getFirstByte(protocol string, environment string, write func(data []byte) (n int, err error), read func(buf []byte) (n int, err error)) error {
	// send a single byte to get a response.
	// This should be at least 1 round trip time, but should be a bit longer.

	oneByte := make([]byte, 1)
	_, err := write(oneByte)
	if err != nil {
		return err
	}

	buf := make([]byte, 8)
	_, errRead := read(buf)
	if errRead != nil {
		return err
	}

	return nil

}

func flood(protocol string, environment string, size int, write func(data []byte) (n int, err error), read func(buf []byte) (n int, err error)) error {

	// start := time.Now()

	finishedSend := make(chan bool)
	finishedRecv := make(chan bool)

	totalSent := 0
	go func(finished chan bool) {
		left := size
		for left > 0 {
			current := min(left, bufferMaxSize)

			_, err := write(dataBuffer[totalSent : totalSent+current])
			if err != nil {
				fmt.Println(err)
				finished <- false
				break
			} else {
				totalSent += current
				left -= current
			}
		}

		finished <- true
	}(finishedSend)

	// var duration time.Duration
	go func(finished chan bool) {
		received := 0
		for received < size {
			buf := make([]byte, 8)
			_, err := read(buf)
			if err != nil {
				fmt.Println(err)
				finished <- false
				break
			}

			sizeString := string(bytes.Trim(buf, "\x00"))
			sizeRecv, _ := strconv.Atoi(sizeString)
			received += int(sizeRecv)
		}
		finished <- true

	}(finishedRecv)

	sendOk := <-finishedSend
	recvOk := <-finishedRecv

	// Code to measure
	// duration := time.Since(start)

	if sendOk && recvOk {
		// report(protocol, environment, "Raw", setupDuration, size, duration)
		return nil
	} else {
		return fmt.Errorf("%s: %d did not finish ", protocol, size)
	}
}

func clientQuicMain(environment string, host string, quicPort int) error {
	fmt.Println("Testing QUIC...")
	protocolName := "QUIC" // for report and logging strings
	url := fmt.Sprintf("%s:%d", host, quicPort)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	size := initialMessageSize
	for size <= finalMessageSize {

		memoryBefore, err2 := memory.Get()
		if err2 != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err2)
			return err2
		}

		cpuBefore, err1 := cpu.Get()
		if err1 != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err1)
			return err1
		}
		// i'm really not sure about this ctx declaration
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // 3s handshake timeout
		defer cancel()
		session, err := quic.DialAddr(ctx, url, tlsConf, nil)
		if err != nil {
			return err
		}
		//
		start := time.Now()
		stream, err := session.OpenStreamSync(context.Background())
		if err != nil {
			return err
		}
		defer stream.Close()
		setupDuration := time.Since(start)
		getFirstByte(protocolName, environment, stream.Write, stream.Read)
		firstByteDuration := time.Since(start)

		floodStart := time.Now()
		for fileNum := 0; fileNum < filesToSend; fileNum++ {
			err = flood(protocolName, environment, size, stream.Write, stream.Read)
		}

		duration := time.Since(floodStart)
		if err != nil {
			fmt.Println(err)
		} else {
			cpuAfter, err1 := cpu.Get()
			if err1 != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err1)
				return err1
			}

			memoryAfter, err2 := memory.Get()
			if err2 != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err2)
				return err2
			}
			report(protocolName, environment, "Raw", filesToSend, setupDuration, firstByteDuration, size, duration, memoryBefore, memoryAfter, cpuBefore, cpuAfter)
		}

		size *= 2
	}
	return nil
}


/**
 * Return the minimum value between a and b
 */
 func min(a int, b int) int {
	if a < b {
		return a
	}

	return b
}
