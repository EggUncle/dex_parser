#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import getopt
import binascii

from dex_header import Dex_header
from dex_map_item import Dex_map_item

dex_header_data = None


def endan_little(hex_data):
    list = []
    for i in range(0, len(hex_data), 2):
        list.append(hex_data[i] + hex_data[i + 1])
    list.reverse()
    return ''.join(list)


def read_file(path):
    with open(path, 'rb') as f:
        dex_data = bytearray(f.read())
    return dex_data


def parse_dex(dex_data):
    parse_dex_header(dex_data)
    parse_map(dex_data)


def parse_map(dex_data):
    print '----------map------------'

    map_off = dex_header_data.map_off
    size = int(endan_little(binascii.b2a_hex(dex_data[map_off:map_off + 4])))
    print 'map list size :', size

    dex_map_items_data = dex_data[map_off:map_off + size * 12]

    map_items = []
    for i in range(0, 12):
        start_offset = i * 12
        end_offset = i * 12 + 12
        map_item_data = endan_little(binascii.b2a_hex(dex_map_items_data[start_offset:end_offset]))
        item_type = map_item_data[0:4]
        item_unused = map_item_data[4:8]
        item_size = map_item_data[8:16]
        item_offset = map_item_data[16:24]
        map_items.append(Dex_map_item(item_type, item_unused, item_size, item_offset))

        # print 'item:'
        print 'type:', item_type
        # print 'unused:', item_unused
        # print 'size:', item_size
        print 'offset:', item_offset


def parse_dex_header(dex_data):
    global dex_header_data

    print '----------header------------'

    dex_hex_data = binascii.b2a_hex(dex_data)
    # dex_hex_data = dex_data
    # read magic
    print len(dex_hex_data)
    magic_set = 0
    magic_offset = 8 * 2
    magic = dex_hex_data[magic_set: magic_offset]
    # magic = struct.unpack('<2L', dex_hex_data[magic_set:magic_offset])
    print magic
    if magic != '6465780a30333500':
        print 'magic error'
        sys.exit()
    m = magic.decode('hex').split('\n')
    magic = m[0]
    version = m[1]
    print 'magic :', magic
    print 'version :', version

    # read checksum
    checksum_set = magic_offset
    checksum_offset = checksum_set + 4 * 2
    checksum = endan_little(dex_hex_data[checksum_set:checksum_offset])
    print 'checksum :', checksum
    # read signature
    signature_set = checksum_offset
    signature_offset = signature_set + 20 * 2
    signature = dex_hex_data[signature_set:signature_offset]
    print 'signature :', signature

    # read file_size
    file_size_set = signature_offset
    file_size_offset = file_size_set + 4 * 2
    file_size = int(endan_little(dex_hex_data[file_size_set:file_size_offset]), 16)
    print 'file_size :', file_size
    # print 'file_size :',len(binascii.a2b_hex(dex_hex_data))
    # read head size
    head_size_set = file_size_offset
    head_size_offset = head_size_set + 4 * 2
    head_size = endan_little(dex_hex_data[head_size_set:head_size_offset])
    print 'head_size :', head_size

    # read endan_tag
    endan_tag_set = head_size_offset
    endan_tag_offset = endan_tag_set + 4 * 2
    endan_tag = dex_hex_data[endan_tag_set:endan_tag_offset]
    print 'endan_tag :', endan_tag

    # skip read_link_size & read_link_off
    link_offset = endan_tag_offset + 4 * 2 * 2

    # read map_off
    map_set = link_offset
    map_offset = map_set + 4 * 2
    map_off = int(endan_little(dex_hex_data[map_set:map_offset]), 16)
    print 'map_off :', map_off

    print ''
    # read string_id_size & string_size_off
    string_id_size_set = map_offset
    string_id_size_offset = string_id_size_set + 4 * 2
    string_id_size = int(endan_little(dex_hex_data[string_id_size_set:string_id_size_offset]), 16)
    print 'string_id_size :', string_id_size
    string_id_off_set = string_id_size_offset
    string_id_off_offset = string_id_off_set + 4 * 2
    string_id_off = int(endan_little(dex_hex_data[string_id_off_set:string_id_off_offset]), 16)
    print 'string_id_off :', string_id_off

    print ''
    # read type_ids_size & type_ids_off
    type_ids_size_set = string_id_off_offset
    type_ids_size_offset = type_ids_size_set + 4 * 2
    type_id_size = int(endan_little(dex_hex_data[type_ids_size_set:type_ids_size_offset]), 16)
    print 'type_id_size :', type_id_size
    type_ids_off_set = type_ids_size_offset
    type_ids_off_offset = type_ids_off_set + 4 * 2
    type_ids_off = int(endan_little(dex_hex_data[type_ids_off_set:type_ids_off_offset]), 16)
    print 'type_ids_off :', type_ids_off

    print ''
    # read proto_ids_size & proto_ids_off
    proto_ids_size_set = type_ids_off_offset
    proto_ids_size_offset = proto_ids_size_set + 4 * 2
    proto_ids_size = int(endan_little(dex_hex_data[proto_ids_size_set:proto_ids_size_offset]), 16)
    print 'proto_ids_size :', proto_ids_size
    proto_ids_off_set = proto_ids_size_offset
    proto_ids_off_offset = proto_ids_off_set + 4 * 2
    proto_ids_off = int(endan_little(dex_hex_data[proto_ids_off_set:proto_ids_off_offset]), 16)
    print 'proto_ids_off :', proto_ids_off

    print ''
    # read field_ids_size & field_ids_off
    field_ids_size_set = proto_ids_off_offset
    field_ids_size_offset = field_ids_size_set + 4 * 2
    field_ids_size = int(endan_little(dex_hex_data[field_ids_size_set:field_ids_size_offset]), 16)
    print 'field_ids_size :', field_ids_size
    field_ids_off_set = field_ids_size_offset
    field_ids_off_offset = field_ids_off_set + 4 * 2
    field_ids_off_off = int(endan_little(dex_hex_data[field_ids_off_set:field_ids_off_offset]), 16)
    print 'field_ids_off_off :', field_ids_off_off

    print ''
    # read method_ids_size & method_ids_off
    method_ids_size_set = field_ids_off_offset
    method_ids_size_offset = method_ids_size_set + 4 * 2
    method_ids_size = int(endan_little(dex_hex_data[method_ids_size_set:method_ids_size_offset]), 16)
    print 'method_ids_size :', method_ids_size
    method_ids_off_set = method_ids_size_offset
    method_ids_off_offset = method_ids_off_set + 4 * 2
    method_ids_off = int(endan_little(dex_hex_data[method_ids_off_set:method_ids_off_offset]), 16)
    print 'method_ids_off :', method_ids_off

    print ''
    # read class_defs_size & class_defs_off
    class_defs_size_set = method_ids_off_offset
    class_defs_size_offset = class_defs_size_set + 4 * 2
    class_defs_size = int(endan_little(dex_hex_data[class_defs_size_set:class_defs_size_offset]), 16)
    print 'class_defs_size :', class_defs_size
    method_defs_off_set = class_defs_size_offset
    method_defs_off_offset = method_defs_off_set + 4 * 2
    method_defs_off = int(endan_little(dex_hex_data[method_defs_off_set:method_defs_off_offset]), 16)
    print 'method_defs_off :', method_defs_off

    print ''
    # read data_size & data_off
    data_size_set = method_defs_off_offset
    data_size_offset = data_size_set + 4 * 2
    data_size = int(endan_little(dex_hex_data[data_size_set:data_size_offset]), 16)
    print 'data_size :', data_size
    data_off_set = data_size_offset
    data_off_offset = data_off_set + 4 * 2
    data_off = int(endan_little(dex_hex_data[data_off_set:data_off_offset]), 16)
    print 'data_off :', data_off

    dex_header_data = Dex_header(magic, version, checksum, signature,
                                 file_size, head_size, endan_tag, map_off,
                                 string_id_size, string_id_off,
                                 type_id_size, type_ids_off,
                                 proto_ids_size, proto_ids_off,
                                 field_ids_size, field_ids_off_off,
                                 method_ids_size, method_ids_off,
                                 class_defs_size, method_defs_off,
                                 data_size, data_off)


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hp:", ["path="])
    except getopt.GetoptError:
        print '-p <dex file path>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print '-p <dex file path>'
            sys.exit()
        elif opt in ("-p", "--path"):
            parse_dex(read_file(arg))


if __name__ == "__main__":
    main(sys.argv[1:])
