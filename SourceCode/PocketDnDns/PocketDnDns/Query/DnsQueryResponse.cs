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
using System.IO;
using System.Net;
using PocketDnDns.Records;

using PocketDnDns.Enums;

namespace PocketDnDns.Query
{
	/// <summary>
	/// Summary description for DnsQueryResponse.
	/// </summary>
	public class DnsQueryResponse : DnsQueryBase
    {
        #region Fields
        private DnsQueryRequest _queryRequest = new DnsQueryRequest();

        private IDnsRecord[] _answers;
        private IDnsRecord[] _authoritiveNameServers;
        private IDnsRecord[] _additionalRecords;
        private int _bytesReceived = 0;
        #endregion Fields

        #region properties
        public DnsQueryRequest QueryRequest
        {
            get { return _queryRequest; }
        }

        public IDnsRecord[] Answers
        {
            get { return _answers; }
        }

        public IDnsRecord[] AuthoritiveNameServers
        {
            get { return _authoritiveNameServers; }
        }

        public IDnsRecord[] AdditionalRecords
        {
            get { return _additionalRecords; }
        }

        public int BytesReceived
        {
            get { return _bytesReceived; }
        }
        #endregion

        /// <summary>
        /// 
        /// </summary>
		public DnsQueryResponse() 
		{
		}
		
		private DnsQueryRequest ParseQuery(ref MemoryStream ms) 
		{
			DnsQueryRequest queryRequest = new DnsQueryRequest();
			
            // Read name
			queryRequest.Name = DnsRecordBase.ParseName(ref ms);
			return queryRequest;
		}

		internal void ParseResponse(byte[] recvBytes) 
		{
			MemoryStream ms = new MemoryStream(recvBytes);
            byte[] flagBytes = new byte[2];
            byte[] transactionId = new byte[2];
			byte[] questions = new byte[2];
			byte[] answerRRs = new byte[2];
			byte[] authorityRRs = new byte[2];
			byte[] additionalRRs = new byte[2];
            byte[] nsType = new byte[2];
            byte[] nsClass = new byte[2];

			this._bytesReceived = recvBytes.Length;

			// Parse DNS Response
			ms.Read(transactionId, 0, 2);
            ms.Read(flagBytes, 0, 2);
			ms.Read(questions, 0, 2);
			ms.Read(answerRRs, 0, 2);
			ms.Read(authorityRRs, 0, 2);
			ms.Read(additionalRRs ,0, 2);

            // Parse Header
            _transactionId = (ushort)IPAddress.NetworkToHostOrder((short)BitConverter.ToUInt16(transactionId, 0));
            _flags = (ushort)IPAddress.NetworkToHostOrder((short)BitConverter.ToUInt16(flagBytes, 0));
            _queryResponse = (QueryResponse)(_flags & (ushort)FlagMasks.QueryResponseMask);
            _opCode = (OpCode)(_flags & (ushort)FlagMasks.OpCodeMask);
            _nsFlags = (NsFlags)(_flags & (ushort)FlagMasks.NsFlagMask);
            _rCode = (RCode)(_flags & (ushort)FlagMasks.RCodeMask);

            // Parse Questions Section
            _questions = (ushort)IPAddress.NetworkToHostOrder((short)BitConverter.ToUInt16(questions, 0));
            _answerRRs = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(answerRRs, 0));
            _authorityRRs = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(authorityRRs, 0));
            _additionalRRs = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(additionalRRs, 0));

            _additionalRecords = new DnsRecordBase[_additionalRRs];
            _answers = new DnsRecordBase[_answerRRs];
            _authoritiveNameServers = new DnsRecordBase[_authorityRRs];
			
			// Parse Queries
			_queryRequest = this.ParseQuery(ref ms);

            // Read dnsType
            ms.Read(nsType, 0, 2);

            // Read dnsClass
            ms.Read(nsClass, 0, 2);

            _nsType = (NsType)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(nsType, 0));
            _nsClass = (NsClass)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(nsClass, 0));

			// Read in Answer Blocks
			for (int i=0; i < _answerRRs; i++)
			{
				_answers[i] = RecordFactory.Create(ref ms);
			}

			// Parse Authority Records
			for (int i=0; i < _authorityRRs; i++) 
			{
                _authoritiveNameServers[i] = RecordFactory.Create(ref ms);
			}

			// Parse Additional Records
			for (int i=0; i < _additionalRRs; i++) 
			{
                _additionalRecords[i] = RecordFactory.Create(ref ms);
			}
		}
	}
}
