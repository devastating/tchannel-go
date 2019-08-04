-- constants
local MAX_TCH_FRAME_SIZE = 65535
local TCH_FRAME_HEADER_SIZE = 16
local DEFAULT_TCP_PORT = 65370 -- enable TChannel dissecting for a port

-- creates Proto objects
local tch_proto = Proto("tchannel", "TChannel Frame Header")
local tch_callreq_proto = Proto("tchannel-callreq", "TChannel Call Request")

-- a function to convert tables of enumerated types to value-string tables
-- i.e., from { "name" = number } to { number = "name" }
local function enumTableToValStringTable(enumTable)
    local t = {}
    for name,num in pairs(enumTable) do
        t[num] = name
    end
    return t
end

local frametype = {
    NONE							=	0,
		INIT_REQ					=	1,
		INIT_RES					=	2,
		CALL_REQ					= 3,
		CALL_RES					= 4,
		CALL_REQ_CONTINUE = 5,
		CALL_RES_CONTINUE = 6,
		PING_REQ					= 7,
		PING_RES					= 8,
		ERROR							= 9,
}
local frametype_valstr = enumTableToValStringTable(frametype)

local csumtype = {
    NONE										=	0,
    CRC32										=	1,
    FRAMHASH_FINGERPRINT32	=	2,
    CRC32C									=	3,
}
local csumtype_valstr = enumTableToValStringTable(csumtype)

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

-- TChannel CallReq fields
local tch_callreq =
{
    flags = ProtoField.uint8("flags", "Flags", base.DEC),
    ttl = ProtoField.uint32 ("ttl", "TTL", base.DEC),
    tracing = ProtoField.bytes("tracing", "Tracing", base.COLON),
    svc_len = ProtoField.uint8("svc_len", "Service Len", base.DEC),
    svc = ProtoField.string("svc_len", "Service", base.UNICODE),
    nth = ProtoField.uint8("nth", "num_headers", base.DEC),
    csum_type = ProtoField.uint8("csum_type", "Checksum Type", base.DEC, csumtype_valstr),
    csum = ProtoField.uint32 ("csum", "Checksum", base.DEC),
}

-- register the ProtoFields
tch_proto.fields = tch_frame_hdr
tch_callreq_proto.fields = tch_callreq

-- forward declarations of helper functions
local dissectTChFrameHeader
local dissectTChCallReq
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

    -- dissect the length field
    tree:add(tch_frame_hdr.size, length_tvbr)

		-- append the INFO column with frame type
		local msgtype_val  = string.format(": %s", frametype_valstr[msgtype_tvbr:uint()])
		pktinfo.cols.info:append(msgtype_val)

		--- start to dissect payload based on frame type
		if msgtype_tvbr:uint() == frametype.CALL_REQ then
			dissectTChCallReq(tvbuf, pktinfo, root, offset+TCH_FRAME_HEADER_SIZE, length_val-TCH_FRAME_HEADER_SIZE)
		end

    return length_val
end

-- offset points at buffer after frame header.
-- frame_sz is the length after frame header.
dissectTChCallReq = function (tvbuf, pktinfo, root, offset, frame_sz)
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

		-- dissect the transport header fields
		local nth_val = nth_tvbr:uint()
		for i=1, nth_val,1
			do
				local k_tvbr, v_tvbr, new_offset = transportHeaderDissect(tvbuf, offset)
				-- we just add transport headers into the proto field now
				-- TODO: do some research to see if it has better support for
				-- random lenght of k/v pairs.
				local kv = string.format(" %s:%s", k_tvbr:string(), v_tvbr:string())
				tree:append_text(kv)
				offset = new_offset
			end

		-- dissect checksum type and checksum.
		local csum_type_tvbr, offset = get_range_helper(tvbuf, offset, 1)
		tree:add(tch_callreq.csum_type, csum_type_tvbr)
		if csum_type_tvbr:uint() ~= csumtype.NONE then
			local csum_tvbr, new_offset = get_range_helper(tvbuf, offset, 4)
			tree:add(tch_callreq.csum, csum_tvbr)
			offset = new_offset
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
