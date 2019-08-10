-- constants
local MAX_TCH_FRAME_SIZE = 65535
local TCH_FRAME_HEADER_SIZE = 16
local DEFAULT_TCP_PORT = 65370 -- enable TChannel dissecting for a port

-- creates Proto objects
local tch_proto = Proto("tchannel", "TChannel Frame Header")
local tch_initreq_proto = Proto("tchannel-initreq", "TChannel Init Request")
local tch_initres_proto = Proto("tchannel-initres", "TChannel Init Response")
local tch_callreq_proto = Proto("tchannel-callreq", "TChannel Call Request")
local tch_callreq_continue_proto = Proto("tchannel-callreq-continue", "TChannel Call Request Continue")
local tch_callres_proto = Proto("tchannel-callres", "TChannel Call Response")
local tch_thrift_proto = Proto("tchannel-thrift", "TChannel Thrift Scheme")
local tch_raw_proto = Proto("tchannel-raw", "TChannel Raw Scheme")

-- a function to convert enum table to a map of enum strings by enum
-- i.e., from { "name" = number } to { number = "name" }
local function toEnumStringByEnum(enumTable)
    local t = {}
    for name,num in pairs(enumTable) do
        t[num] = name
    end
    return t
end

local frametype = {
    NONE							=	0,
		INIT_REQ					=	0x01,
		INIT_RES					=	0x02,
		CALL_REQ					= 0x03,
		CALL_RES					= 0x04,
		CALL_REQ_CONTINUE = 0x13,
		CALL_RES_CONTINUE = 0x14,
		PING_REQ					= 0xd0,
		PING_RES					= 0xd1,
		ERROR							= 0xFF,
}
local frametype_valstr = toEnumStringByEnum(frametype)

local csumtype = {
    NONE										=	0,
    CRC32										=	1,
    FRAMHASH_FINGERPRINT32	=	2,
    CRC32C									=	3,
}
local csumtype_valstr = toEnumStringByEnum(csumtype)

local rescode = {
	OK = 0x0,
	Error = 0x1,
}
local rescode_valstr = toEnumStringByEnum(rescode)

local astype = {
	NONE = 0,
	THRIFT = 1,
	STHRIFT = 2,
	JSON = 3,
	HTTP = 4,
	RAW = 5,
}

----------------------------------------
-- TChannel frame headers
local tch_frame_hdr =
{
    size   = ProtoField.uint16("tch.length", "Length", base.DEC),
    msg_type  = ProtoField.uint8 ("tch.type", "Type", base.DEC, frametype_valstr),
    reserved1 = ProtoField.uint8 ("tch.reserved1", "Reserved1", base.DEC),
    id = ProtoField.uint32 ("tch.id", "ID", base.DEC),
    reservedP1 = ProtoField.uint64 ("tch.reserved", "Reserved", base.DEC),
}

-- TChannel InitReq fields
local tch_initreq =
{
    version = ProtoField.uint16("version", "Version", base.DEC),
    nh = ProtoField.uint16("nh", "Num of Headers", base.DEC),
    key = ProtoField.string("key", "Key", base.UNICODE),
    val = ProtoField.string("value", "Value", base.UNICODE),
}

local tch_initres =
{
    version = ProtoField.uint16("version", "Version", base.DEC),
    nh = ProtoField.uint16("nh", "Num of Headers", base.DEC),
    key = ProtoField.string("key", "Key", base.UNICODE),
    val = ProtoField.string("value", "Value", base.UNICODE),
}

-- TChannel CallReq fields
local tch_callreq =
{
    flags = ProtoField.uint8("flags", "Flags", base.DEC),
    ttl = ProtoField.uint32 ("ttl", "TTL", base.DEC),
    tracing = ProtoField.bytes("tracing", "Tracing", base.COLON),
    svc = ProtoField.string("svc", "Service", base.UNICODE),
    nth = ProtoField.uint8("nth", "Num of Headers", base.DEC),
    csum_type = ProtoField.uint8("csum_type", "Checksum Type", base.DEC, csumtype_valstr),
    csum = ProtoField.uint32 ("csum", "Checksum", base.HEX),
    as = ProtoField.string("arg_scheme", "Arg Scheme", base.UNICODE),
    cn = ProtoField.string("caller", "Caller Name", base.UNICODE),
    th = ProtoField.string("transport_header", "Other Transport Header", base.UNICODE),
}

-- TChannel CallReq Continue fields
local tch_callreq_continue =
{
    flags = ProtoField.uint8("flags", "Flags", base.DEC),
    csum_type = ProtoField.uint8("csum_type", "Checksum Type", base.DEC, csumtype_valstr),
    csum = ProtoField.uint32 ("csum", "Checksum", base.HEX),
    continuation = ProtoField.bytes("continuation", "Continuation", base.COLON),
}

-- TChannel CallRes fields
-- Most of the fields are sharing with CallReq.
local tch_callres =
{
    code = ProtoField.uint8("code", "Code", base.DEC, rescode_valstr),
}

-- TChannel Thrift Arg Scheme
local tch_thrift =
{
    arg1 = ProtoField.string("arg1", "Arg1", base.UNICODE),
    arg2 = ProtoField.string("arg2", "Arg2 Header", base.UNICODE),
    arg3 = ProtoField.bytes("arg3", "Arg3", base.COLON),
}

local raw_args = {
	arg = ProtoField.bytes("arg", "Arg", base.COLON),
}

-- register the ProtoFields
tch_proto.fields = tch_frame_hdr
tch_initreq_proto.fields = tch_initreq
tch_initres_proto.fields = tch_initres
tch_callreq_proto.fields = tch_callreq
tch_callreq_continue_proto.fields = tch_callreq_continue
tch_callres_proto.fields = tch_callres
tch_thrift_proto.fields = tch_thrift
tch_raw_proto.fields = raw_args

-- forward declarations of helper functions
local dissectTChFrameHeader
local dissectTChInitReqRes
local dissectTChCallReq
local dissectTChCallReqContinue
local dissectTChCallRes
local dissectTChThrift
local dissectTChRaw
local dissectChecksum
local createSllTvb
local checkTChFrameLength
local get_range_helper
local get_var_helper
local get_kv_helper
local transportHeaderDissect

--------------------------------------------------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "tch_proto.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
tch_proto.dissector = function (tvbuf, pktinfo, root)
    local pktlen = tvbuf:len()

    local bytes_consumed = 0
    while bytes_consumed < pktlen do
        local result = dissectTChFrameHeader(tvbuf, pktinfo, root, bytes_consumed)

        if result > 0 then
            bytes_consumed = bytes_consumed + result
            -- try to dissect another packet
        elseif result == 0 then
            -- If the result is 0, then it means we hit an error of some kind,
            -- so return 0. Returning 0 tells Wireshark this packet is not for
            -- us, and it will try heuristic dissectors or the plain "data"
            -- one, which is what should happen in this case.
            return 0
        else
            -- we need more bytes, so set the desegment_offset to what we
            -- already consumed, and the desegment_len to how many more
            -- are needed
            pktinfo.desegment_offset = bytes_consumed

            -- invert the negative result so it's a positive number
            result = -result

            pktinfo.desegment_len = result

            -- even though we need more bytes, this packet is for us, so we
            -- tell wireshark all of its bytes are for us by returning the
            -- number of Tvb bytes we "successfully processed", namely the
            -- length of the Tvb
            return pktlen
        end
    end

    -- In a TCP dissector, you can either return nothing, or return the number of
    -- bytes of the tvbuf that belong to this protocol, which is what we do here.
    -- Do NOT return the number 0, or else Wireshark will interpret that to mean
    -- this packet did not belong to your protocol, and will try to dissect it
    -- with other protocol dissectors (such as heuristic ones)
    return bytes_consumed
end

function dissectTChFrameHeader(tvbuf, pktinfo, root, offset)
    local length_val, length_tvbr = checkTChFrameLength(tvbuf, offset)
    if length_val <= 0 then
        return length_val
    end

    -- if we got here, then we have a whole tchannel frame in the Tvb buffer.

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("tchannel")

    -- set the INFO column too, but only if we haven't already set it before
    -- for this frame, because this function can be called multiple
    -- times per packet/Tvb
    if string.find(tostring(pktinfo.cols.info), "^tchannel") == nil then
        pktinfo.cols.info:set("tchannel")
    end

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(tch_proto, tvbuf:range(offset, TCH_FRAME_HEADER_SIZE))

    -- dissect the type field
    local msgtype_tvbr = tvbuf:range(offset + 2, 1)
    tree:add(tch_frame_hdr.msg_type, msgtype_tvbr)

    -- dissect the message ID field
    local msgid_tvbr = tvbuf:range(offset + 4, 4)
    tree:add(tch_frame_hdr.id, msgid_tvbr)

    -- dissect the length field
    tree:add(tch_frame_hdr.size, length_tvbr)

		-- append the INFO column with frame type
		local msgtype_val  = string.format(": %s", frametype_valstr[msgtype_tvbr:uint()])
		pktinfo.cols.info:append(msgtype_val)

		local has_thrift = false
		local next_offset = offset+TCH_FRAME_HEADER_SIZE
		local left_length = length_val-TCH_FRAME_HEADER_SIZE
		--- start to dissect payload based on frame type
		if msgtype_tvbr:uint() == frametype.CALL_REQ then
			dissectTChCallReq(tvbuf, pktinfo, root, next_offset, left_length)
		elseif msgtype_tvbr:uint() == frametype.CALL_REQ_CONTINUE then
			dissectTChCallReqContinue(tvbuf, pktinfo, root, next_offset, left_length)
		elseif msgtype_tvbr:uint() == frametype.CALL_RES then
			dissectTChCallRes(tvbuf, pktinfo, root, next_offset, left_length)
		elseif msgtype_tvbr:uint() == frametype.INIT_REQ then
			dissectTChInitReqRes(tch_initreq_proto, tvbuf, pktinfo, root, next_offset, left_length)
		elseif msgtype_tvbr:uint() == frametype.INIT_RES then
			dissectTChInitReqRes(tch_initres_proto, tvbuf, pktinfo, root, next_offset, left_length)
		end

    return length_val
end

-- same dissector for INIT_REQ and INIT_RES
function dissectTChInitReqRes(proto, tvbuf, pktinfo, root, offset, frame_sz)
    local tree = root:add(proto, tvbuf:range(offset, frame_sz))
		-- dissect version
		local ver_tvbr, offset = get_range_helper(tvbuf, offset, 2)
    tree:add(tch_initreq.version, ver_tvbr)

		-- dissect number of headers
		local nh_tvbr, offset = get_range_helper(tvbuf, offset, 2)
    tree:add(tch_initreq.nh, nh_tvbr)

		-- dissect kv headers
		local nh = nh_tvbr:uint()
		for i=1, nh, 1
			do
				local key_tvbr, val_tvbr, new_offset = get_kv_helper(tvbuf, offset, 2, 2)
				tree:add(tch_initreq.key, key_tvbr)
				tree:add(tch_initreq.val, val_tvbr)
				offset = new_offset
			end
end

-- offset points at buffer after frame header.
-- frame_sz is the length after frame header.
dissectTChCallReq = function (tvbuf, pktinfo, root, offset, frame_sz)
		local start_offset = offset
    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(tch_callreq_proto, tvbuf:range(offset, frame_sz))

    -- dissect the flag field
		local flags_tvbr, offset = get_range_helper(tvbuf, offset, 1)
    tree:add(tch_callreq.flags, flags_tvbr)

    -- dissect the TTL field
    local ttl_tvbr, offset = get_range_helper(tvbuf, offset, 4)
    tree:add(tch_callreq.ttl, ttl_tvbr)

    -- dissect the tracing field
		local tracing_tvbr, offset = get_range_helper(tvbuf, offset, 25)
    tree:add(tch_callreq.tracing, tracing_tvbr)

    -- dissect the svc length
		local svc_tvbr, offset = get_var_helper(tvbuf, offset, 1)
    tree:add(tch_callreq.svc, svc_tvbr)

    -- dissect the nth field
		local nth_tvbr, offset = get_range_helper(tvbuf, offset, 1)
    tree:add(tch_callreq.nth, nth_tvbr)

		local arg_scheme = nil
		-- dissect the transport header fields
		local nth_val = nth_tvbr:uint()
		local other_th = {}
		for i=1, nth_val,1
			do
				local required_transport_hdrs = {
					as = tch_callreq.as,
					cn = tch_callreq.cn,
				}

				local k_tvbr, v_tvbr, new_offset = transportHeaderDissect(tvbuf, offset)
				local hdr_field = required_transport_hdrs[k_tvbr:string()]
				if hdr_field then
					tree:add(hdr_field, v_tvbr)
				else
					local kv = string.format("%s:%s", k_tvbr:string(), v_tvbr:string())
					-- insert other transport headers later so that we always show
					-- Arg Scheme or Caller Name first.
					table.insert(other_th, kv)
				end
				offset = new_offset

				if (k_tvbr:string() == "as") then
					arg_scheme = v_tvbr:string()
				end
			end

		for k, v in pairs(other_th) do
			tree:add(tch_callreq.th, v)
		end

		-- dissect checksum type and checksum.
		local csum_type_tvbr, csum_tvbr, offset = dissectChecksum(tvbuf, offset)
		tree:add(tch_callreq.csum_type, csum_type_tvbr)
		if csum_tvbr ~= nil then
			tree:add(tch_callreq.csum, csum_tvbr)
		end

		-- update the length properly before tch_thrift
		local parsed = offset-start_offset
		tree:set_len(parsed)

		-- TODO: we only process non-fragmented call for thrift for now
		-- since we only have the info for which arg is which.
		if (arg_scheme == "thrift") and (flags_tvbr:uint() == 0) then
			dissectTChThrift(tvbuf, pktinfo, root, offset, frame_sz-parsed)
		elseif arg_scheme == "raw" then
			dissectTChRaw(tvbuf, pktinfo, root, offset, frame_sz-parsed)
		end
end

function dissectTChCallReqContinue(tvbuf, pktinfo, root, offset, frame_sz)
		local start_offset = offset
    local tree = root:add(tch_callreq_continue_proto, tvbuf:range(offset, frame_sz))
    -- dissect the flag field
		local flags_tvbr, offset = get_range_helper(tvbuf, offset, 1)
    tree:add(tch_callreq_continue.flags, flags_tvbr)

		-- dissect checksum type and value
		local csum_type_tvbr, csum_tvbr, offset = dissectChecksum(tvbuf, offset)
		tree:add(tch_callreq_continue.csum_type, csum_type_tvbr)
		if csum_tvbr ~= nil then
			tree:add(tch_callreq.csum, csum_tvbr)
		end

		local continuation_tvbr, offset = get_range_helper(tvbuf, offset, frame_sz-(offset-start_offset))
		tree:add(tch_callreq_continue.continuation, continuation_tvbr)
end

dissectTChCallRes = function (tvbuf, pktinfo, root, offset, frame_sz)
		local start_offset = offset
    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(tch_callres_proto, tvbuf:range(offset, frame_sz))

    -- dissect the flag field
		local flags_tvbr, offset = get_range_helper(tvbuf, offset, 1)
    tree:add(tch_callreq.flags, flags_tvbr)

    -- dissect the code field
		local code_tvbr, offset = get_range_helper(tvbuf, offset, 1)
    tree:add(tch_callres.code, code_tvbr)

    -- dissect the tracing field
		local tracing_tvbr, offset = get_range_helper(tvbuf, offset, 25)
    tree:add(tch_callreq.tracing, tracing_tvbr)

    -- dissect the nth field
		local nth_tvbr, offset = get_range_helper(tvbuf, offset, 1)
    tree:add(tch_callreq.nth, nth_tvbr)

		local arg_scheme = nil
		-- dissect the transport header fields
		local nth_val = nth_tvbr:uint()
		local other_th = {}
		for i=1, nth_val,1
			do
				local required_transport_hdrs = {
					as = tch_callreq.as,
					cn = tch_callreq.cn,
				}

				local k_tvbr, v_tvbr, new_offset = transportHeaderDissect(tvbuf, offset)
				local hdr_field = required_transport_hdrs[k_tvbr:string()]
				if hdr_field then
					tree:add(hdr_field, v_tvbr)
				else
					local kv = string.format("%s:%s", k_tvbr:string(), v_tvbr:string())
					-- insert other transport headers later so that we always show
					-- Arg Scheme or Caller Name first.
					table.insert(other_th, kv)
				end
				offset = new_offset

				if (k_tvbr:string() == "as") then
					arg_scheme = v_tvbr:string()
				end
			end

		for k, v in pairs(other_th) do
			tree:add(tch_callreq.th, v)
		end

		-- dissect checksum type and checksum.
		local csum_type_tvbr, csum_tvbr, offset = dissectChecksum(tvbuf, offset)
		tree:add(tch_callreq.csum_type, csum_type_tvbr)
		if csum_tvbr ~= nil then
			tree:add(tch_callreq.csum, csum_tvbr)
		end

		-- update the length properly before tch_thrift
		local parsed = offset-start_offset
		tree:set_len(parsed)

		-- TODO: we only process non-fragmented call for thrift for now
		-- since we only have the info for which arg is which.
		if (arg_scheme == "thrift") and (flags_tvbr:uint() == 0) then
			dissectTChThrift(tvbuf, pktinfo, root, offset, frame_sz-parsed)
		elseif arg_scheme == "raw" then
			dissectTChRaw(tvbuf, pktinfo, root, offset, frame_sz-parsed)
		end
end

function dissectChecksum(tvbuf, offset)
		local csum_type_tvbr, offset = get_range_helper(tvbuf, offset, 1)
		if csum_type_tvbr:uint() ~= csumtype.NONE then
			local csum_tvbr, new_offset = get_range_helper(tvbuf, offset, 4)
			return csum_type_tvbr, csum_tvbr, new_offset
		end

		return csum_type_tvbr, nil, offset
end

function dissectTChThrift(tvbuf, pktinfo, root, offset, frame_sz)
    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(tch_thrift_proto, tvbuf:range(offset, frame_sz))

		-- dissect the Arg1
		local arg1_tvbr, offset = get_var_helper(tvbuf, offset, 2)
		tree:add(tch_thrift.arg1, arg1_tvbr)

		-- dissect the Arg2
		-- TODO: add safety check to handle corrupted packets.
		local arg2_len_tvbr, offset = get_range_helper(tvbuf, offset, 2)
		local arg2_count_tvbr, offset = get_range_helper(tvbuf, offset, 2)
		local arg2_count = arg2_count_tvbr:uint()
		for i=1, arg2_count, 1
			do
				-- TODO: not sure if it's a good idea to present arg2 kv as string.
				local key_tvbr, val_tvbr, new_offset = get_kv_helper(tvbuf, offset, 2, 2)
				tree:add(tch_thrift.arg2, string.format("%s:%s", key_tvbr:string(), val_tvbr:string()))
				offset = new_offset
			end

		-- dissect the Arg3
		-- TODO: add safety check to handle corrupted packets.
		local arg3_len_tvbr, offset = get_range_helper(tvbuf, offset, 2)
		local arg3_val_tvbr, offset = get_range_helper(tvbuf, offset, arg3_len_tvbr:uint())
		tree:add(tch_thrift.arg3, arg3_val_tvbr)
end

function dissectTChRaw(tvbuf, pktinfo, root, offset, frame_sz)
    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(tch_raw_proto, tvbuf:range(offset, frame_sz))

		-- dissect the Args
		local end_offset = offset + frame_sz
		while offset < end_offset do
			local arg1_len_tvbr, new_offset = get_range_helper(tvbuf, offset, 2)
			offset = new_offset
			if arg1_len_tvbr:uint() > 0 then
				local arg1_val_tvbr, new_offset = get_range_helper(tvbuf, offset, arg1_len_tvbr:uint())
				tree:add(raw_args.arg, arg1_val_tvbr)
				offset = new_offset
			end
		end
end

----------------------------------------
-- The function to check the length field.
--
-- This returns two things: (1) the length, and (2) the TvbRange object, which
-- might be nil if length <= 0.
function checkTChFrameLength(tvbuf, offset)

    -- "msglen" is the number of bytes remaining in the Tvb buffer which we
    -- have available to dissect in this run
    local msglen = tvbuf:len() - offset

    -- check if capture was only capturing partial packet size
    if msglen ~= tvbuf:reported_length_remaining(offset) then
        -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
        return 0
    end

    if msglen < TCH_FRAME_HEADER_SIZE then
        -- we need more bytes, so tell the main dissector function that we
        -- didn't dissect anything, and we need an unknown number of more
        -- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
        -- return as a negative number
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- if we got here, then we know we have enough bytes in the Tvb buffer
    -- to at least figure out the full length of this tchannel frame.

    -- get the TvbRange of bytes 1+2
    local length_tvbr = tvbuf:range(offset, 2)

    -- get the length as an unsigned integer, in network-order (big endian)
    local length_val  = length_tvbr:uint()

    if length_val > MAX_TCH_FRAME_SIZE then
        -- too many bytes, invalid message
        return 0
    end

    if msglen < length_val then
        return -(length_val - msglen)
    end

    return length_val, length_tvbr
end

function transportHeaderDissect(tvbuf, offset)
	-- transport header has (hk~1, hv~1)
	return get_kv_helper(tvbuf, offset, 1, 1)
end

-- returns key/value Tvb range and new offset with k~key_len and v~val_len
function get_kv_helper(tvbuf, offset, key_len, val_len)
	local key_tvbr, offset = get_var_helper(tvbuf, offset, key_len)
	local val_tvbr, offset = get_var_helper(tvbuf, offset, val_len)
	return key_tvbr, val_tvbr, offset
end

-- return var range and new offset with var~size_len
function get_var_helper(tvbuf, offset, size_len)
	local len_tvbr, offset = get_range_helper(tvbuf, offset, size_len)
	return get_range_helper(tvbuf, offset, len_tvbr:uint())
end

-- get_range_helper returns Tvb range and new offset after taking the range
function get_range_helper(tvbuf, offset, len)
	local tvbr = tvbuf:range(offset, len)
	return tvbr, offset+len
end

-- always enable dissector
DissectorTable.get("tcp.port"):add(DEFAULT_TCP_PORT, tch_proto)
