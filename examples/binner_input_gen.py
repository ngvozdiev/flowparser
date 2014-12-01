import binner_pb2

binner_config = binner_pb2.BinnerConfig()
binner_config.pcap_filename = '/Users/nik/caida_uncompressed/equinix-sanjose.dirA.20130117-125912.UTC.anon.pcap'

bin_pack_config = binner_config.bin_pack_configs.add()
bin_pack_config.type = binner_pb2.BinPack.SIZES_BYTES

bin_pack_config = binner_config.bin_pack_configs.add()
bin_pack_config.type = binner_pb2.BinPack.SIZES_PKTS

bin_pack_config = binner_config.bin_pack_configs.add()
bin_pack_config.type = binner_pb2.BinPack.NEW_FLOWS

bin_pack_config = binner_config.bin_pack_configs.add()
bin_pack_config.type = binner_pb2.BinPack.ACTIVE_FLOWS

f = open('binner_input.proto', 'wb')
f.write(binner_config.SerializeToString())
f.close()
