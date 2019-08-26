package.prepend_path('lrc4')
local rc4 = require('rc4')

local dissector_data = Dissector.get('data')

local MSG_HEADER_LEN = 8
local MSG_HEADER_ENDPOINT_OFFSET = 0
local MSG_HEADER_FLAGS_OFFSET = 1
local MSG_HEADER_DEV_PORT_OFFSET = 2
local MSG_HEADER_TAG_OFFSET = 3
local MSG_HEADER_PAYLOAD_LEN_OFFSET = 4
local MSG_PAYLOAD_OFFSET = 8

local TAG_ENDPOINT_TRANSFER_ENQUEUE = 0x00
local TAG_ENDPOINT_TRANSFER_ENQUEUE_AND_GO = 0xFF
local TAG_DEVICE_SETUP_REQUEST = 0x01
local TAG_DEVICE_SETUP_RESPONSE = 0x02
local TAG_PING_RESPONSE = 0x03
local TAG_PING_REQUEST = 0x04
local TAG_DETACH_DEVICE_REQUEST = 0x05
local TAG_DETACH_DEVICE_RESPONSE = 0x06
local TAG_EP_SETUP = 0x07
local TAG_STATUS_REQUEST = 0x08
local TAG_STATUS_RESPONSE = 0x09
local TAG_HTTP_PORT_REQUEST = 0x0A
local TAG_HTTP_PORT_RESPONSE = 0x0B

local vs_tag = {
    [TAG_ENDPOINT_TRANSFER_ENQUEUE] = 'Endpoint Transfer Enqueue',
    [TAG_ENDPOINT_TRANSFER_ENQUEUE_AND_GO] = 'Endpoint Transfer Enqueue and Go',
    [TAG_DEVICE_SETUP_REQUEST] = 'Device Setup',
    [TAG_DEVICE_SETUP_RESPONSE] = 'Device Setup Response',
    [TAG_EP_SETUP] = 'USB EP Setup',
    [TAG_STATUS_REQUEST] = 'Status Request',
    [TAG_STATUS_RESPONSE] = 'Status Response',
    [TAG_HTTP_PORT_REQUEST] = 'HTTP Port Request',
    [TAG_HTTP_PORT_RESPONSE] = 'HTTP Port Response',
    [TAG_DETACH_DEVICE_REQUEST] = 'Detach Device Request',
    [TAG_DETACH_DEVICE_RESPONSE] = 'Detach Device Response',
    [TAG_PING_REQUEST] = 'Ping Request',
    [TAG_PING_RESPONSE] = 'Ping Response'
}

local vs_ep_type = {
    [1] = 'Bulk Out',
    [2] = 'Bulk In',
    [3] = 'Interrupt In'
}

local p_usbanywhere = Proto('usbanywhere', 'USBAnywhere')
p_usbanywhere.prefs.rc4_key = Pref.string('RC4 Decryption Key', 'BX80570E3110Q814A447', '')
local msg_fields = {
    -- Header
    tag = ProtoField.uint8('usbanywhere.tag', 'Tag', base.HEX, vs_tag),
    dev_port = ProtoField.uint8('usbanywhere.dev_port', 'Device Port', base.DEC),

    ep = ProtoField.uint8('usbanywhere.ep', 'Endpoint', base.HEX),
    ep_num = ProtoField.uint8('usbanywhere.ep.num', 'Number', base.DEC, nil, 0x0F),
    ep_type = ProtoField.uint8('usbanywhere.ep.type', 'Type', base.DEC, vs_ep_type, 0xF0),

    flags = ProtoField.uint8('usbanywhere.flags', 'Flags', base.HEX),
    flags_encrypted = ProtoField.bool('usbanywhere.flags.encrypted', 'Encrypted', 8, nil, 0x80),

    unknown = ProtoField.uint8('usbanywhere.unknown', 'Unknown', base.HEX),
    payload_len = ProtoField.uint32('usbanywhere.payload_len', 'Payload Length', base.DEC),

    -- Device Setup packet header
    device_setup_username = ProtoField.string('usbanywhere.device_setup.username', 'Username', base.ASCII),
    device_setup_password = ProtoField.string('usbanywhere.device_setup.password', 'Password', base.ASCII),
    device_setup_flags = ProtoField.uint8('usbanywhere.device_setup.flags', 'Flags', base.HEX),
    device_setup_flags_username_is_session_id = ProtoField.bool(
        'usbanywhere.device_setup.flags.username_is_session_id',
        'Username is session ID',
        8,
        nil,
        0x80
    ),
    device_setup_flags_check_auth_only = ProtoField.bool(
        'usbanywhere.device_setup.flags.check_auth_only',
        'Check auth only',
        8,
        nil,
        0x40
    ),
    device_setup_flags_desired_port = ProtoField.uint8(
        'usbanywhere.device_setup.flags.desired_port',
        'Requested Port',
        base.DEC,
        nil,
        0x0E
    ),
    device_setup_flags_allocate_port = ProtoField.bool(
        'usbanywhere.device_setup.flags.allocate_port',
        'Allocate Port',
        8,
        nil,
        0x01
    )
}
p_usbanywhere.fields = msg_fields

local dissectVirtualMedia = function(tvbuf, pktinfo, root, offset)
    local msgbuf = tvbuf(offset)
    local msgbuflen = tvbuf:len() - offset

    -- Ignore any cut-off packets.
    if msgbuflen ~= tvbuf:reported_length_remaining(offset) then
        print(
            string.format(
                'Packet %d: Ignore cut-off packet MsgBufLen=%d MsgReportedLenRemaining=%d',
                pktinfo.number,
                msgbuflen,
                tvbuf:reported_length_remaining(offset)
            )
        )
        return 0
    end

    -- Ignore any packets that are too small to have a payload length.
    if msgbuflen < MSG_HEADER_LEN then
        print(string.format('Packet %d: Too short Len=%d', pktinfo.number, msgbuflen))
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- Extract header fields for later use.
    local tag = msgbuf(MSG_HEADER_TAG_OFFSET, 1):le_uint()
    local dev_port = msgbuf(MSG_HEADER_DEV_PORT_OFFSET, 1):le_uint()
    local ep_num = msgbuf(MSG_HEADER_ENDPOINT_OFFSET, 1):bitfield(4, 4)

    -- Ignore any packets that have an unknown tag.
    if not vs_tag[tag] then
        print(string.format('Packet %d: Dropping due to unknown tag: %d', pktinfo.number, tag))
        return 0
    end

    -- Determine payload length.
    local is_encrypted = msgbuf(1, 1):bitfield(0)
    local payload_len = msgbuf(4, 4):le_uint()
    if tag == TAG_DEVICE_SETUP_REQUEST then
        -- Determine actual length by walking descriptors after payload
        payload_len = msgbuf(8):len()
    end

    -- Request reassembly as necessary to acquire full payload.
    local msglen = MSG_HEADER_LEN + payload_len
    if msgbuflen < msglen then
        return -(msglen - msgbuflen)
    end

    -- Decrypt payload
    local payload = nil
    if payload_len > 0 then
        payload = msgbuf(MSG_PAYLOAD_OFFSET, payload_len):tvb()

        if is_encrypted == 1 then
            print(string.format('RC4 Key: %s', p_usbanywhere.prefs.rc4_key))
            local rc4_engine = rc4(p_usbanywhere.prefs.rc4_key)
            payload = ByteArray.new(rc4_engine(payload:raw()), true):tvb('Decrypted Payload')
        end
    end

    -- Fill in columns
    pktinfo.cols.protocol:set('USBAnywhere')
    if string.find(tostring(pktinfo.cols.info), '^VirtMedia') == nil then
        pktinfo.cols.info:set(string.format('VirtMedia %s, Port %d, Endpoint: %d', vs_tag[tag], dev_port, ep_num))
        if is_encrypted == 1 then
            pktinfo.cols.info:append(' (encrypted)')
        end
    else
        pktinfo.cols.info:append(', and more...')
    end

    -- Build protocol subtree
    local subtree = root:add(p_usbanywhere, msgbuf(0, msglen))
    subtree:append_text(string.format(', Tag: %s, Port %d, Endpoint: %d, Len: %d', vs_tag[tag], dev_port, ep_num, msglen))
    if is_encrypted == 1 then
        subtree:append_text(' (encrypted)')
    end
    subtree:add_packet_field(msg_fields.tag, msgbuf(MSG_HEADER_TAG_OFFSET, 1), ENC_LITTLE_ENDIAN)
    subtree:add_packet_field(msg_fields.dev_port, msgbuf(MSG_HEADER_DEV_PORT_OFFSET, 1), ENC_LITTLE_ENDIAN)
    local endpoint_tree = subtree:add_packet_field(msg_fields.ep, msgbuf(MSG_HEADER_ENDPOINT_OFFSET, 1), ENC_LITTLE_ENDIAN)
    local flag_tree = subtree:add_packet_field(msg_fields.flags, msgbuf(MSG_HEADER_FLAGS_OFFSET, 1), ENC_LITTLE_ENDIAN)
    subtree:add_packet_field(msg_fields.payload_len, msgbuf(MSG_HEADER_PAYLOAD_LEN_OFFSET, 4), ENC_LITTLE_ENDIAN)

    endpoint_tree:add_packet_field(msg_fields.ep_num, msgbuf(MSG_HEADER_ENDPOINT_FLAGS_OFFSET, 1), ENC_LITTLE_ENDIAN)
    endpoint_tree:add_packet_field(msg_fields.ep_type, msgbuf(MSG_HEADER_ENDPOINT_FLAGS_OFFSET, 1), ENC_LITTLE_ENDIAN)

    flag_tree:add_packet_field(msg_fields.flags_encrypted, msgbuf(MSG_HEADER_FLAGS_OFFSET, 1), ENC_LITTLE_ENDIAN)

    if payload ~= nil then
        if tag == TAG_DEVICE_SETUP_REQUEST then
            local device_setup_tree = root:add('Virtual Media Device Setup Request')
            device_setup_tree:add_packet_field(msg_fields.device_setup_username, payload(0, 16), ENC_LITTLE_ENDIAN)
            device_setup_tree:add_packet_field(msg_fields.device_setup_password, payload(0x10, 20), ENC_LITTLE_ENDIAN)
            local device_setup_flags_tree =
                device_setup_tree:add_packet_field(msg_fields.device_setup_flags, payload(0x28, 1), ENC_LITTLE_ENDIAN)

            device_setup_flags_tree:add_packet_field(
                msg_fields.device_setup_flags_username_is_session_id,
                payload(0x28, 1),
                ENC_LITTLE_ENDIAN
            )
            device_setup_flags_tree:add_packet_field(
                msg_fields.device_setup_flags_check_auth_only,
                payload(0x28, 1),
                ENC_LITTLE_ENDIAN
            )
            device_setup_flags_tree:add_packet_field(
                msg_fields.device_setup_flags_desired_port,
                payload(0x28, 1),
                ENC_LITTLE_ENDIAN
            )
            device_setup_flags_tree:add_packet_field(
                msg_fields.device_setup_flags_allocate_port,
                payload(0x28, 1),
                ENC_LITTLE_ENDIAN
            )
        else
            dissector_data:call(payload, pktinfo, root)
        end
    end

    return msglen
end

function p_usbanywhere.dissector(tvbuf, pktinfo, root)
    local pktlen = tvbuf:len()
    local bytes_consumed = 0

    while bytes_consumed < pktlen do
        local result = dissectVirtualMedia(tvbuf, pktinfo, root, bytes_consumed)
        if result > 0 then
            -- go again on another while loop
            -- we successfully processed an FPM message, of 'result' length
            bytes_consumed = bytes_consumed + result
        elseif result == 0 then
            -- If the result is 0, then it means we hit an error of some kind,
            -- so return 0. Returning 0 tells Wireshark this packet is not for
            -- us, and it will try heuristic dissectors or the plain "data"
            -- one, which is what should happen in this case.
            print(string.format('Encountered error'))
            return 0
        else
            -- invert the negative result so it's a positive number of additional bytes required.
            result = -result

            -- we need more bytes, so set the desegment_offset to what we
            -- already consumed, and the desegment_len to how many more
            -- are needed
            pktinfo.desegment_offset = bytes_consumed
            pktinfo.desegment_len = result

            -- even though we need more bytes, this packet is for us, so we
            -- tell wireshark all of its bytes are for us by returning the
            -- number of Tvb bytes we "successfully processed", namely the
            -- length of the Tvb
            return pktlen
        end
    end

    return bytes_consumed
end

local tcp_encap_table = DissectorTable.get('tcp.port')
tcp_encap_table:add(623, p_usbanywhere)
