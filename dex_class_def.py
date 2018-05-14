#!/usr/bin/python
# -*- coding: UTF-8 -*-

class Dex_class_def(object):
    def __init__(self, class_idx, access_flags, superclass_idx, interfaces_off,
                 source_file_idx, annotations_off,
                 class_data_off, static_values_off):
        self.class_idx = class_idx
        self.access_flags = access_flags
        self.superclass_idx = superclass_idx
        self.interfaces_off = interfaces_off
        self.source_file_idx = source_file_idx
        self.annotations_off = annotations_off
        self.class_data_off = class_data_off
        self.static_values_off = static_values_off


class Dex_class_data(object):
    def __init__(self, header, static_fields, instance_fields, direct_methods,
                 virtual_methods):
        self.header = header
        self.static_fields = static_fields
        self.instance_fields = instance_fields
        self.direct_methods = direct_methods
        self.virtual_methods = virtual_methods


class Dex_class_deta_header(object):
    def __init__(self, staitc_fields_size, instance_fields_size, direct_methods_size,
                 virtual_methods_size):
        self.staitc_fields_size = staitc_fields_size
        self.instance_fields_size = instance_fields_size
        self.direct_methods_size = direct_methods_size
        self.virtual_methods_size = virtual_methods_size


class Dex_field(object):
    def __init__(self, field_idx, access_flags):
        self.field_idx = field_idx
        self.access_flags = access_flags


class Dex_method(object):
    def __init__(self, method_idx, access_flags, code_off):
        self.method_idx = method_idx
        self.access_flags = access_flags
        self.code_off = code_off
