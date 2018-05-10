#!/usr/bin/python
# -*- coding: UTF-8 -*-


class Dex_header(object):
    def __init__(self, magic, version, checksum, signature,
                 file_size, head_size, endan_tag, map_off,
                 string_id_size, string_id_off,
                 type_id_size, type_ids_off,
                 proto_ids_size, proto_ids_off,
                 field_ids_size, field_ids_off_off,
                 method_ids_size, method_ids_off,
                 class_defs_size, method_defs_off,
                 data_size, data_off):
        self.magic = magic
        self.version = version
        self.checksum = checksum
        self.signature = signature
        self.file_size = file_size
        self.head_size = head_size
        self.endan_tag = endan_tag
        self.map_off = map_off
        self.string_id_size = string_id_size
        self.string_id_off = string_id_off
        self.type_id_size = type_id_size
        self.type_ids_off = type_ids_off
        self.proto_ids_size = proto_ids_size
        self.proto_ids_off = proto_ids_off
        self.field_ids_size = field_ids_size
        self.field_ids_off_off = field_ids_off_off
        self.method_ids_size = method_ids_size
        self.method_ids_off = method_ids_off
        self.class_defs_size = class_defs_size
        self.method_defs_off = method_defs_off
        self.data_size = data_size
        self.data_off = data_off
