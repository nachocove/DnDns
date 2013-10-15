/**********************************************************************
 * Copyright (c) 2010, j. montgomery                                  *
 * All rights reserved.                                               *
 *                                                                    *
 * Redistribution and use in source and binary forms, with or without *
 * modification, are permitted provided that the following conditions *
 * are met:                                                           *
 *                                                                    *
 * + Redistributions of source code must retain the above copyright   *
 *   notice, this list of conditions and the following disclaimer.    *
 *                                                                    *
 * + Redistributions in binary form must reproduce the above copyright*
 *   notice, this list of conditions and the following disclaimer     *
 *   in the documentation and/or other materials provided with the    *
 *   distribution.                                                    *
 *                                                                    *
 * + Neither the name of j. montgomery's employer nor the names of    *
 *   its contributors may be used to endorse or promote products      *
 *   derived from this software without specific prior written        *
 *   permission.                                                      *
 *                                                                    *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS*
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT  *
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS  *
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE     *
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,*
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES           *
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR *
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) *
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,*
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED*
 * OF THE POSSIBILITY OF SUCH DAMAGE.                                 *
 **********************************************************************/
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using DnDns.Enums;
using DnDns.Query;
using DnDns.Records;
using DnDns.Security;

namespace DnDnsExamples
{
    class Program
    {
        static void Main(string[] args)
        {
            // Test TCP request
            DnsQueryRequest request = new DnsQueryRequest();
            DnsQueryResponse response = request.Resolve("www.google.com", NsType.A, NsClass.INET, ProtocolType.Tcp);

            OutputResults(response);

            // Test UDP request
            DnsQueryRequest request2 = new DnsQueryRequest();
            DnsQueryResponse response2 = request.Resolve("www.google.com", NsType.A, NsClass.INET, ProtocolType.Udp);

            OutputResults(response2);

            // Example usage of security provider.
            // DnsQueryRequest request3 = new DnsQueryRequest();
            // DnsQueryResponse response3 = request3.Resolve("a.tsig.secured.server", "a.server.to.lookup", NsType.A, NsClass.INET, ProtocolType.Udp, new TsigMessageSecurityProvider("sharedkeyname", "shared key as base 64 string", 300));

            Console.ReadLine();
        }

        private static void OutputResults(DnsQueryResponse response)
        {
            Console.WriteLine("Bytes received: " + response.BytesReceived);

            Console.WriteLine("Name: " + response.Name);
            Console.WriteLine("OpCode: " + response.NsClass);
            Console.WriteLine("NsFlags: " + response.NsFlags);
            Console.WriteLine("NsType: " + response.NsType);
            Console.WriteLine("RCode: " + response.RCode);
            Console.WriteLine("OpCode: " + response.OpCode);
            
            // Enumerate the Answer Records
            Console.WriteLine("Answers:");
            foreach (IDnsRecord record in response.Answers)
            {
                Console.WriteLine(record.Answer);
                Console.WriteLine("  |--- RDATA Field Length: " + record.DnsHeader.DataLength);
                Console.WriteLine("  |--- Name: " + record.DnsHeader.Name);
                Console.WriteLine("  |--- NS Class: " + record.DnsHeader.NsClass);
                Console.WriteLine("  |--- NS Type: " + record.DnsHeader.NsType);
                Console.WriteLine("  |--- TTL: " + record.DnsHeader.TimeToLive);
                Console.WriteLine();
            }

            foreach (IDnsRecord record in response.AuthoritiveNameServers)
            {
                Console.WriteLine(record.Answer);
                Console.WriteLine("  |--- RDATA Field Length: " + record.DnsHeader.DataLength);
                Console.WriteLine("  |--- Name: " + record.DnsHeader.Name);
                Console.WriteLine("  |--- NS Class: " + record.DnsHeader.NsClass);
                Console.WriteLine("  |--- NS Type: " + record.DnsHeader.NsType);
                Console.WriteLine("  |--- TTL: " + record.DnsHeader.TimeToLive);
                Console.WriteLine();
            }

            foreach (IDnsRecord record in response.AdditionalRRecords)
            {
                Console.WriteLine(record.Answer);
                Console.WriteLine("  |--- RDATA Field Length: " + record.DnsHeader.DataLength);
                Console.WriteLine("  |--- Name: " + record.DnsHeader.Name);
                Console.WriteLine("  |--- NS Class: " + record.DnsHeader.NsClass);
                Console.WriteLine("  |--- NS Type: " + record.DnsHeader.NsType);
                Console.WriteLine("  |--- TTL: " + record.DnsHeader.TimeToLive);
                Console.WriteLine();
            }
        }
    }
}

