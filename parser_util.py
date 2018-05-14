#!/usr/bin/python
# -*- coding: UTF-8 -*-

import binascii

import sys

from dex_field_id import Dex_field_id
from dex_header import Dex_header
from dex_map_item import Dex_map_item
from dex_method_id import Dex_method_id
from dex_proto_id import Dex_proto_id, Dex_type_list, Dex_type_item

map_type_dict = {
    '0000': 'kDexTypeHeaderItem',
    '0001': 'kDexTypeStringIdItem',
    '0002': 'kDexTypeTypeIdItem',
    '0003': 'kDexTypeProtoIdItem',
    '0004': 'kDexTypeFieldIdItem',
    '0005': 'kDexTypeMethodIdItem',
    '0006': 'kDexTypeClassDefItem',
    '1000': 'kDexTypeMapList',
    '1001': 'kDexTypeTypeList',
    '1002': 'kDexTypeAnnotationSetRefList',
    '1003': 'kDexTypeAnnotationSetItem',
    '2000': 'kDexTypeClassDataItem',
    '2001': 'kDexTypeCodeItem',
    '2002': 'kDexTypeStringDataItem',
    '2003': 'kDexTypeDebugInfoItem',
    '2004': 'kDexTypeAnnotationItem',
    '2005': 'kDexTypeEncodedArrayItem',
    '2006': 'kDexTypeAnnotationsDirectoryItem',
}


def endan_little(hex_data):
    list = []
    for i in range(0, len(hex_data), 2):
        list.append(hex_data[i] + hex_data[i + 1])
    list.reverse()
    return ''.join(list)


def parse_dex_header(dex_data):
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
    print 'file_size :', file_size, endan_little(dex_hex_data[file_size_set:file_size_offset])
    # print 'file_size :',len(binascii.a2b_hex(dex_hex_data))
    # read head size
    head_size_set = file_size_offset
    head_size_offset = head_size_set + 4 * 2
    head_size = endan_little(dex_hex_data[head_size_set:head_size_offset])
    print 'head_size :'

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
    print 'map_off :', map_off, endan_little(dex_hex_data[map_set:map_offset])

    print ''
    # read string_id_size & string_size_off
    string_id_size_set = map_offset
    string_id_size_offset = string_id_size_set + 4 * 2
    string_id_size = int(endan_little(dex_hex_data[string_id_size_set:string_id_size_offset]), 16)
    print 'string_id_size :', string_id_size, endan_little(dex_hex_data[string_id_size_set:string_id_size_offset])
    string_id_off_set = string_id_size_offset
    string_id_off_offset = string_id_off_set + 4 * 2
    string_id_off = int(endan_little(dex_hex_data[string_id_off_set:string_id_off_offset]), 16)
    print 'string_id_off :', string_id_off, endan_little(dex_hex_data[string_id_off_set:string_id_off_offset])

    print ''
    # read type_ids_size & type_ids_off
    type_ids_size_set = string_id_off_offset
    type_ids_size_offset = type_ids_size_set + 4 * 2
    type_id_size = int(endan_little(dex_hex_data[type_ids_size_set:type_ids_size_offset]), 16)
    print 'type_id_size :', type_id_size, endan_little(dex_hex_data[type_ids_size_set:type_ids_size_offset])
    type_ids_off_set = type_ids_size_offset
    type_ids_off_offset = type_ids_off_set + 4 * 2
    type_ids_off = int(endan_little(dex_hex_data[type_ids_off_set:type_ids_off_offset]), 16)
    print 'type_ids_off :', type_ids_off, endan_little(dex_hex_data[type_ids_off_set:type_ids_off_offset])

    print ''
    # read proto_ids_size & proto_ids_off
    proto_ids_size_set = type_ids_off_offset
    proto_ids_size_offset = proto_ids_size_set + 4 * 2
    proto_ids_size = int(endan_little(dex_hex_data[proto_ids_size_set:proto_ids_size_offset]), 16)
    print 'proto_ids_size :', proto_ids_size, endan_little(dex_hex_data[proto_ids_size_set:proto_ids_size_offset])
    proto_ids_off_set = proto_ids_size_offset
    proto_ids_off_offset = proto_ids_off_set + 4 * 2
    proto_ids_off = int(endan_little(dex_hex_data[proto_ids_off_set:proto_ids_off_offset]), 16)
    print 'proto_ids_off :', proto_ids_off, endan_little(dex_hex_data[proto_ids_off_set:proto_ids_off_offset])

    print ''
    # read field_ids_size & field_ids_off
    field_ids_size_set = proto_ids_off_offset
    field_ids_size_offset = field_ids_size_set + 4 * 2
    field_ids_size = int(endan_little(dex_hex_data[field_ids_size_set:field_ids_size_offset]), 16)
    print 'field_ids_size :', field_ids_size, endan_little(dex_hex_data[field_ids_size_set:field_ids_size_offset])
    field_ids_off_set = field_ids_size_offset
    field_ids_off_offset = field_ids_off_set + 4 * 2
    field_ids_off_off = int(endan_little(dex_hex_data[field_ids_off_set:field_ids_off_offset]), 16)
    print 'field_ids_off_off :', field_ids_off_off, endan_little(dex_hex_data[field_ids_off_set:field_ids_off_offset])

    print ''
    # read method_ids_size & method_ids_off
    method_ids_size_set = field_ids_off_offset
    method_ids_size_offset = method_ids_size_set + 4 * 2
    method_ids_size = int(endan_little(dex_hex_data[method_ids_size_set:method_ids_size_offset]), 16)
    print 'method_ids_size :', method_ids_size, endan_little(dex_hex_data[method_ids_size_set:method_ids_size_offset])
    method_ids_off_set = method_ids_size_offset
    method_ids_off_offset = method_ids_off_set + 4 * 2
    method_ids_off = int(endan_little(dex_hex_data[method_ids_off_set:method_ids_off_offset]), 16)
    print 'method_ids_off :', method_ids_off, endan_little(dex_hex_data[method_ids_off_set:method_ids_off_offset])

    print ''
    # read class_defs_size & class_defs_off
    class_defs_size_set = method_ids_off_offset
    class_defs_size_offset = class_defs_size_set + 4 * 2
    class_defs_size = int(endan_little(dex_hex_data[class_defs_size_set:class_defs_size_offset]), 16)
    print 'class_defs_size :', class_defs_size, endan_little(dex_hex_data[class_defs_size_set:class_defs_size_offset])
    method_defs_off_set = class_defs_size_offset
    method_defs_off_offset = method_defs_off_set + 4 * 2
    method_defs_off = int(endan_little(dex_hex_data[method_defs_off_set:method_defs_off_offset]), 16)
    print 'method_defs_off :', method_defs_off, endan_little(dex_hex_data[method_defs_off_set:method_defs_off_offset])

    print ''
    # read data_size & data_off
    data_size_set = method_defs_off_offset
    data_size_offset = data_size_set + 4 * 2
    data_size = int(endan_little(dex_hex_data[data_size_set:data_size_offset]), 16)
    print 'data_size :', data_size, endan_little(dex_hex_data[data_size_set:data_size_offset])
    data_off_set = data_size_offset
    data_off_offset = data_off_set + 4 * 2
    data_off = int(endan_little(dex_hex_data[data_off_set:data_off_offset]), 16)
    print 'data_off :', data_off, endan_little(dex_hex_data[data_off_set:data_off_offset])

    return Dex_header(magic, version, checksum, signature,
                      file_size, head_size, endan_tag, map_off,
                      string_id_size, string_id_off,
                      type_id_size, type_ids_off,
                      proto_ids_size, proto_ids_off,
                      field_ids_size, field_ids_off_off,
                      method_ids_size, method_ids_off,
                      class_defs_size, method_defs_off,
                      data_size, data_off)


def parse_map(dex_data, dex_header_data):
    print '----------map------------'

    map_off = dex_header_data.map_off
    size = int(endan_little(binascii.b2a_hex(dex_data[map_off:map_off + 4])), 16)
    print 'map list size :', size

    dex_map_items_data = dex_data[map_off + 4:map_off + 4 + size * 12]
    map_items = []
    for i in range(0, size):
        start_offset = i * 12
        end_offset = i * 12 + 12
        map_item_data = binascii.b2a_hex(dex_map_items_data[start_offset:end_offset])
        item_type = endan_little(map_item_data[0:4])
        item_unused = endan_little(map_item_data[4:8])
        item_size = endan_little(map_item_data[8:16])
        item_offset = endan_little(map_item_data[16:24])
        map_items.append(Dex_map_item(item_type, item_unused, item_size, item_offset))

        print ''
        print 'map item: ', i
        print 'type:', item_type, map_type_dict[item_type]
        print 'unused:', item_unused
        print 'size:', item_size
        print 'offset:', item_offset

    return map_items


def parse_map_items(dex_data, map_items):
    print '--------------map items----------------'
    str_list = []
    type_list = []
    proto_list = []
    field_list = []
    method_list = []
    for item in map_items:
        ty = item.type
        if ty == '0001':
            print '--------------string items----------------'
            str_list = parse_string_items(dex_data, item)
        elif ty == '0002':
            print '--------------type items----------------'
            type_list = parse_type_items(dex_data, item, str_list)
        elif ty == '0003':
            print '--------------proto items----------------'
            proto_list = parse_proto_items(dex_data, item, str_list, type_list)
        elif ty == '0004':
            print '--------------field items----------------'
            field_list = parse_field_items(dex_data, item, str_list, type_list)
        elif ty == '0005':
            print '--------------method items----------------'
            method_list = parse_method_items(dex_data, item, str_list, type_list, proto_list)
        elif ty == '0006':
            print '--------------class items----------------'
            parse_class_def_items(dex_data, item, str_list, type_list, field_list, method_list)


def parse_string_items(dex_data, map_item):
    size = int(map_item.size, 16)
    offset = int(map_item.offset, 16)
    data = dex_data[offset:offset + size * 4]
    str_list = []
    for i in range(0, size):
        d_start = i * 4
        d_end = i * 4 + 4
        string_data_off_data = data[d_start:d_end]
        string_data_off = bytedata_to_int(string_data_off_data)
        # 这里对size的长度处理可能比较粗暴,如果细化处理这里应该根据uleb128来解析
        string_size = bytedata_to_int(dex_data[string_data_off:string_data_off + 1])
        # print string_data_off, string_size
        string_data = dex_data[string_data_off + 1:string_data_off + 1 + string_size]
        sstring = ''
        for j in range(0, string_size):
            j_start = j
            j_end = j + 1
            string = chr(bytedata_to_int(string_data[j_start:j_end]))
            sstring = sstring + string
        # print string_data_off, i, sstring
        str_list.append(sstring)

    return str_list


def parse_type_items(dex_data, map_item, str_list):
    size = int(map_item.size, 16)
    offset = int(map_item.offset, 16)
    data = dex_data[offset:offset + size * 4]
    type_list = []
    for i in range(0, size):
        d_start = i * 4
        d_end = i * 4 + 4
        index = bytedata_to_int(data[d_start:d_end])
        # print str_list[index]
        type_list.append(str_list[index])

    return type_list


def parse_proto_items(dex_data, map_item, str_list, type_list):
    size = int(map_item.size, 16)
    offset = int(map_item.offset, 16)
    data = dex_data[offset:offset + size * 12]
    proto_list = []
    for i in range(0, size):
        d_start = i * 12
        d_end = i * 12 + 12
        item_data = data[d_start:d_end]
        shorty_idx = bytedata_to_int(item_data[0:4])
        return_type_idx = bytedata_to_int(item_data[4:8])
        parameters_off = bytedata_to_int(item_data[8:12])

        shorty = str_list[shorty_idx]
        return_type = type_list[return_type_idx]
        type_list_size = 0
        if parameters_off != 0:
            type_list_size = bytedata_to_int(dex_data[parameters_off:parameters_off + 4])
        type_list_data = dex_data[parameters_off + 4:parameters_off + 4 + type_list_size * 2]
        type_items = ''

        proto_id = Dex_proto_id(shorty_idx, return_type_idx, parameters_off)
        item_list = []
        dex_type_list = Dex_type_list(type_list_size, item_list)

        for j in range(0, type_list_size):
            j_start = j * 2
            j_end = j * 2 + 2
            type_idx = bytedata_to_int(type_list_data[j_start:j_end])
            type_item = type_list[type_idx]
            type_items = type_items + type_item + ' '
            type_item = Dex_type_item(type_idx)
            dex_type_list.add_type_item_list(type_item)

        proto_id.set_type_list(dex_type_list)
        proto_list.append(proto_id)
        # print shorty, return_type, type_items

    return proto_list


def parse_field_items(dex_data, map_item, str_list, type_list):
    size = int(map_item.size, 16)
    offset = int(map_item.offset, 16)
    data = dex_data[offset:offset + size * 8]
    field_list = []
    for i in range(0, size):
        i_start = i * 8
        i_end = i * 8 + 8
        item_data = data[i_start:i_end]
        class_idx = bytedata_to_int(item_data[0:2])
        type_idx = bytedata_to_int(item_data[2:4])
        name_idx = bytedata_to_int(item_data[4:8])
        field_list.append(Dex_field_id(class_idx, type_idx, name_idx))
        # print ''
        # print 'class:', type_list[class_idx]
        # print 'type:', type_list[type_idx]
        # print 'name:', str_list[name_idx]

    return field_list


def parse_method_items(dex_data, map_item, str_list, type_list, proto_list):
    size = int(map_item.size, 16)
    offset = int(map_item.offset, 16)
    data = dex_data[offset:offset + size * 8]
    method_list = []
    for i in range(0, size):
        i_start = i * 8
        i_end = i * 8 + 8
        item_data = data[i_start:i_end]
        class_idx = bytedata_to_int(item_data[0:2])
        proto_idx = bytedata_to_int(item_data[2:4])
        name_idx = bytedata_to_int(item_data[4:8])

        class_data = type_list[class_idx]
        proto_data = proto_list[proto_idx]
        name_data = str_list[name_idx]
        print ''
        print 'class :', class_data
        print 'proto :', print_proto(proto_data, str_list, type_list)
        print 'name :', name_data
        method_list.append(Dex_method_id(class_idx, proto_idx, name_idx))

    return method_list


def parse_class_def_items(dex_data, map_item, str_list, type_list, field_list, method_list):
    pass


def print_proto(proto, str_list, type_list):
    shorty_idx = proto.shorty_idx
    return_type_idx = proto.return_type_idx

    dex_type_list = proto.dex_type_list.type_item_list
    ty_str = ''
    for t in dex_type_list:
        type_idx = t.type_idx
        ty = type_list[type_idx]
        ty_str = ty_str + ' ' + ty

    shorty = str_list[shorty_idx]
    return_type = type_list[return_type_idx]
    result = 'shorty: ' + shorty + ' type: ' + ty_str + ' return type ' + return_type
    return result


def bytedata_to_int(data):
    return int(endan_little(binascii.b2a_hex(data)), 16)
