package RmiiRx;

import FIFOF::*;
import GetPut::*;
import EthCrc::*;

// IEEE 802.3 帧在 RMII 上的接收：CRS_DV 有效期间每拍收 2 比特，LSB 先到。
// 前导码 0x55 x7 + SFD 0xD5 之后是净荷，末 4 字节为 FCS。
typedef enum { Idle, Sync, Data } RxState deriving (Bits, Eq, FShow);

typedef struct {
  Bit#(8) dat;
  Bool    last;
  Bool    fcsOk;   // 仅在 last 时有意义
} RxByte deriving (Bits, FShow);

interface RmiiRxPins;
  (* always_ready, always_enabled, prefix = "" *)
  method Action wire_in((* port = "rxd"    *) Bit#(2) rxd,
                        (* port = "crs_dv" *) Bool    crs_dv,
                        (* port = "rx_er"  *) Bool    rx_er);
endinterface

interface RmiiRxIfc;
  interface RmiiRxPins pins;
  interface Get#(RxByte) rx;
endinterface

(* synthesize *)
(* default_clock_osc = "clk", default_reset = "rst_n" *)
module mkRmiiRx(RmiiRxIfc);
  FIFOF#(RxByte) outQ <- mkSizedFIFOF(8);

  // 引脚经 RWire 进入规则域：wset 在前、wget 在后，同拍可见，避免多打一拍。
  RWire#(Tuple3#(Bit#(2), Bool, Bool)) pinW <- mkRWire;

  Reg#(RxState)  st   <- mkReg(Idle);
  Reg#(Bit#(8))  acc  <- mkReg(0);
  Reg#(Bit#(2))  dib  <- mkReg(0);
  Reg#(Bit#(32)) crc  <- mkReg(crcInit);
  Reg#(Bool)     err  <- mkReg(False);

  // 收齐一字节：新双比特补到高位，四拍后自然复原 LSB 先出的字节
  function Bit#(8) shiftIn(Bit#(8) a, Bit#(2) d) = {d, a[7:2]};

  rule recv (pinW.wget matches tagged Valid {.rxd, .dv, .rxer});
    if (!dv) begin
      // 载波消失即帧尾。CRC 跑过净荷与 FCS 后应落在固定余数上。
      if (st == Data) outQ.enq(RxByte { dat: 0, last: True, fcsOk: (crc == 32'hDEBB20E3) && !err });
      st <= Idle; dib <= 0; acc <= 0; crc <= crcInit; err <= False;
    end else begin
      Bit#(8) nx = shiftIn(acc, rxd);
      if (rxer) err <= True;

      if (dib != 3) begin
        dib <= dib + 1; acc <= nx;
      end else begin
        dib <= 0; acc <= 0;
        case (st)
          Idle: if (nx == 8'hD5) st <= Data;          // 前导码全部丢弃，只认 SFD
                else if (nx != 8'h55) st <= Sync;      // 非法起始，等本帧结束
          Sync: noAction;
          Data: begin
            crc <= crc32Byte(crc, nx);
            outQ.enq(RxByte { dat: nx, last: False, fcsOk: False });
          end
        endcase
      end
    end
  endrule

  interface RmiiRxPins pins;
    method Action wire_in(Bit#(2) rxd, Bool crs_dv, Bool rx_er);
      pinW.wset(tuple3(rxd, crs_dv, rx_er));
    endmethod
  endinterface

  interface rx = toGet(outQ);
endmodule

endpackage
