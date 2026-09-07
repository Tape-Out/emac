package RmiiTx;

import FIFOF::*;
import GetPut::*;
import EthCrc::*;

typedef enum { Idle, Preamble, Sfd, Payload, Fcs, Ifg } TxState deriving (Bits, Eq, FShow);

// 引脚侧全部 always_ready，生成的 Verilog 才是裸线而非带握手的方法端口。
interface RmiiTxPins;
  (* always_ready, result="txd"   *) method Bit#(2) txd;
  (* always_ready, result="tx_en" *) method Bool    tx_en;
endinterface

interface RmiiTxIfc;
  interface RmiiTxPins pins;
  interface Put#(Tuple2#(Bit#(8), Bool)) tx;
endinterface

(* synthesize *)
(* default_clock_osc = "clk", default_reset = "rst_n" *)
module mkRmiiTx(RmiiTxIfc);
  FIFOF#(Tuple2#(Bit#(8), Bool)) inQ <- mkSizedFIFOF(4);

  Reg#(TxState)  st    <- mkReg(Idle);
  Reg#(Bit#(8))  sh    <- mkReg(8'h55);
  Reg#(Bit#(2))  dib   <- mkReg(0);
  Reg#(Bit#(3))  pre   <- mkReg(0);
  Reg#(Bit#(32)) crc   <- mkReg(crcInit);
  Reg#(Bit#(32)) fcsSh <- mkReg(0);
  Reg#(Bit#(2))  fcsI  <- mkReg(0);
  Reg#(Bool)     lastB <- mkReg(False);
  Reg#(Bit#(6))  ifg   <- mkReg(0);
  Reg#(Bit#(2))  txdR  <- mkReg(0);
  Reg#(Bool)     enR   <- mkReg(False);

  Bool bd = (dib == 3);   // 本字节最后一个双比特

  // 取数动作单列一条规则，避免 inQ 的隐式条件被提升到整个发送流程上，
  // 否则末字节 deq 后 FIFO 变空会让发送整体停摆。
  function Action driveAndStep(Bit#(8) nextSh);
    return action
      txdR <= sh[1:0];
      enR  <= True;
      sh   <= nextSh;
      dib  <= bd ? 0 : dib + 1;
    endaction;
  endfunction

  rule startFrame (st == Idle && inQ.notEmpty);
    st <= Preamble; sh <= 8'h55; dib <= 0; pre <= 0;
    crc <= crcInit; fcsI <= 0;
  endrule

  rule shiftMid ((st == Preamble || st == Sfd || st == Payload || st == Fcs) && !bd);
    driveAndStep({2'b0, sh[7:2]});
  endrule

  rule preambleNext (st == Preamble && bd);
    driveAndStep(pre == 6 ? 8'hD5 : 8'h55);
    if (pre == 6) st <= Sfd; else pre <= pre + 1;
  endrule

  rule sfdNext (st == Sfd && bd);
    match {.b, .l} = inQ.first; inQ.deq;
    driveAndStep(b);
    crc <= crc32Byte(crc, b);
    lastB <= l; st <= Payload;
  endrule

  rule payloadNext (st == Payload && bd && !lastB);
    match {.b, .l} = inQ.first; inQ.deq;
    driveAndStep(b);
    crc <= crc32Byte(crc, b);
    lastB <= l;
  endrule

  rule payloadLast (st == Payload && bd && lastB);
    Bit#(32) f = ~crc;
    driveAndStep(f[7:0]);
    fcsSh <= f; fcsI <= 0; st <= Fcs;
  endrule

  rule fcsNext (st == Fcs && bd);
    if (fcsI == 3) begin
      txdR <= sh[1:0]; enR <= True; dib <= 0;
      st <= Ifg; ifg <= 0;
    end else begin
      driveAndStep(fcsSh[15:8]);
      fcsSh <= fcsSh >> 8; fcsI <= fcsI + 1;
    end
  endrule

  // 96 bit times 帧间隔，2bit/周期故 48 拍
  rule interFrameGap (st == Ifg);
    enR <= False; txdR <= 0;
    if (ifg == 47) st <= Idle; else ifg <= ifg + 1;
  endrule

  interface RmiiTxPins pins;
    method Bit#(2) txd   = txdR;
    method Bool    tx_en = enR;
  endinterface

  interface tx = toPut(inQ);
endmodule

endpackage
