package EthCrc;

// 以太网 FCS 按字节 LSB 先出，故用反射多项式 0xEDB88320 而非 0x04C11DB7。
function Bit#(32) crc32Byte(Bit#(32) crc, Bit#(8) dat);
  Bit#(32) c = crc ^ zeroExtend(dat);
  for (Integer i = 0; i < 8; i = i + 1)
    c = (c[0] == 1) ? (c >> 1) ^ 32'hEDB88320 : (c >> 1);
  return c;
endfunction

Bit#(32) crcInit = 32'hFFFFFFFF;

endpackage
