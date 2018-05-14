#!/usr/bin/python
# -*- coding: UTF-8 -*-

# 方法声明结构体
class Dex_proto_id(object):
    def __init__(self, shorty_idx, return_type_idx, parameters_off):
        self.shorty_idx = shorty_idx  # 指向dex string id列表的索引
        self.return_type_idx = return_type_idx  # 指向dex type id 列表的索引
        self.parameters_off = parameters_off  # 指向dex type list的偏移

    def set_type_list(self, size, type_item_list):
        self.dex_type_list = Dex_type_list(size, type_item_list)


class Dex_type_list(object):
    def __init__(self, size, type_item_list):
        self.size = size
        self.type_item_list = type_item_list

    def add_type_item_list(self, type_idx):
        self.type_item_list.append(Dex_type_item(type_idx))
        pass


class Dex_type_item(object):
    def __init__(self, type_idx):
        self.type_idx = type_idx
