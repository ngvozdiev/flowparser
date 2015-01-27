import binner_pb2

binner_config = binner_pb2.BinnerConfig()
binner_config.pcap_filename = '/Users/nik/out'

bin_pack_config = binner_config.bin_pack_configs.add()
bin_pack_config.type = binner_pb2.BinPack.SIZES_BYTES

bin_pack_config = binner_config.bin_pack_configs.add()
bin_pack_config.type = binner_pb2.BinPack.SIZES_PKTS

bin_pack_config = binner_config.bin_pack_configs.add()
bin_pack_config.type = binner_pb2.BinPack.NEW_FLOWS

bin_pack_config = binner_config.bin_pack_configs.add()
bin_pack_config.type = binner_pb2.BinPack.ACTIVE_FLOWS

bin_pack_config = binner_config.bin_pack_configs.add()
bin_pack_config.type = binner_pb2.BinPack.END_TIMESTAMP

f = open('binner_input.pb', 'wb')
f.write(binner_config.SerializeToString())
f.close()
