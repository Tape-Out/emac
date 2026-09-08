package Emac;

import Vector::*;
import GetPut::*;
import ConfigReg::*;
import RegIf::*;
import RmiiTx::*;
import RmiiRx::*;
import EmacRegs::*;

// 本包不认识任何总线：对外只给中立的 RegIf，接哪种总线由 wrap 或装配决定。
//
// 本版是**缓冲区式** MAC：一帧一个缓冲区，软件填好写长度即发，收到一帧置位状态
// 让软件来取。不做描述符环——那要发起口能仲裁，与 dma 的散列聚集是同一件待办。
typedef struct {
  Bool promisc;
} EmacCfg;

interface EmacPins;
  interface RmiiTxPins tx;
  interface RmiiRxPins rx;
endinterface

interface EmacIfc#(numeric type aw, numeric type dw, numeric type bufWords);
  interface RegIf#(aw, dw) regs;
  interface EmacPins       pins;
  (* always_ready *) method Bool irq;
endinterface

module mkEmac#(EmacCfg cfg)(EmacIfc#(aw, dw, bufWords))
    provisos (Mul#(TDiv#(dw, 8), 8, dw), Add#(_a, 12, aw), Add#(_b, 1, dw),
              Add#(_c, 32, dw), Add#(_d, 16, dw), Add#(_e, 11, dw),
              Add#(_f, 2, dw), Log#(TAdd#(bufWords, 1), _g),
              Add#(_h, TLog#(TAdd#(bufWords, 1)), 12),
              Add#(_i, TLog#(TAdd#(bufWords, 1)), 11));

  EmacRegsIfc#(aw, dw, bufWords) r <- mkEmacRegs;
  RmiiTxIfc tx <- mkRmiiTx;
  RmiiRxIfc rx <- mkRmiiRx;

  Reg#(Bool)      txRun  <- mkConfigReg(False);
  Reg#(Bit#(11))  txLeft <- mkReg(0);
  Reg#(Bit#(11))  txPos  <- mkReg(0);
  Reg#(Bool)      txPend <- mkReg(False);

  Reg#(Bit#(11))  rxPos  <- mkConfigReg(0);
  Reg#(Bit#(48))  rxDst  <- mkConfigReg(0);
  Reg#(Bool)      rxDrop <- mkConfigReg(False);
  Reg#(Bit#(11))  rxLen  <- mkConfigReg(0);
  Reg#(Bool)      rxFull <- mkConfigReg(False);
  Reg#(Bool)      fcsBad <- mkConfigReg(False);
  Reg#(Bit#(32))  rxWord <- mkReg(0);

  // 接收落在缓冲区上半，发送在下半。半分点是编译期常数，不占逻辑。
  Integer half = valueOf(bufWords) / 2;

  // swmod 的脉冲与寄存器的新值差一拍，先记脉冲、下一拍再取长度
  rule mark;
    txPend <= r.txlen_wr;
  endrule

  rule startTx (txPend && !txRun && r.ctrl_en == 1);
    txRun  <= True;
    txLeft <= r.txlen;
    txPos  <= 0;
  endrule

  rule sendByte (txRun && txLeft != 0);
    Bit#(32) w = r.frame[txPos >> 2];
    Bit#(8)  b = case (txPos[1:0])
                   0: w[7:0];
                   1: w[15:8];
                   2: w[23:16];
                   default: w[31:24];
                 endcase;
    tx.tx.put(tuple2(b, txLeft == 1));
    txPos  <= txPos + 1;
    txLeft <= txLeft - 1;
  endrule

  rule endTx (txRun && txLeft == 0);
    txRun <= False;
    r.ista_set(2'b01);
  endrule

  rule recvByte (!rxFull);
    let x <- rx.rx.get;
    if (x.last) begin
      // 末尾那一拍只带校验结果，不带数据
      // 被过滤掉的帧不叫醒软件，缓冲区留给下一帧
      rxFull <= !rxDrop;
      rxLen  <= rxDrop ? 0 : rxPos;
      fcsBad <= !x.fcsOk;
      rxPos  <= 0;
      rxDrop <= False;
      if (!rxDrop) r.ista_set(2'b10);
    end else if (rxPos < 6) begin
      // 前六个字节是目的地址。不开混杂模式就只收自己的与广播的，
      // 收完第六个字节当场决定这一帧还要不要往下写。
      Bit#(48) nd = {rxDst[39:0], x.dat};
      rxDst <= nd;
      if (rxPos == 5 && !cfg.promisc) begin
        Bit#(48) me = {r.machi, r.maclo};
        rxDrop <= (nd != me) && (nd != 48'hFFFF_FFFF_FFFF);
      end
      Bit#(11) p = rxPos + fromInteger(half * 4);
      Bit#(32) w = r.frame[p >> 2];
      Bit#(32) nw = case (p[1:0])
                      0: {w[31:8],  x.dat};
                      1: {w[31:16], x.dat, w[7:0]};
                      2: {w[31:24], x.dat, w[15:0]};
                      default: {x.dat, w[23:0]};
                    endcase;
      r.frame_in(truncate(p >> 2), nw);
      rxPos <= rxPos + 1;
    end else if (!rxDrop && rxPos < fromInteger(half * 4)) begin
      Bit#(11) p = rxPos + fromInteger(half * 4);
      Bit#(32) w = r.frame[p >> 2];
      Bit#(32) nw = case (p[1:0])
                      0: {w[31:8],  x.dat};
                      1: {w[31:16], x.dat, w[7:0]};
                      2: {w[31:24], x.dat, w[15:0]};
                      default: {x.dat, w[23:0]};
                    endcase;
      r.frame_in(truncate(p >> 2), nw);
      rxPos <= rxPos + 1;
    end
  endrule

  // 软件读过 rxlen 就把缓冲区放回去，等下一帧
  rule rearm (r.rxlen_rd && rxFull);
    rxFull <= False;
    fcsBad <= False;
  endrule

  // volatile 字段：没有存储，硬件每拍驱动
  rule status;
    r.rxlen_in(rxLen);
    r.status_txbusy_in(txRun ? 1 : 0);
    r.status_rxfull_in(rxFull ? 1 : 0);
    r.status_fcserr_in(fcsBad ? 1 : 0);
  endrule

  interface regs = r.regs;
  interface EmacPins pins;
    interface tx = tx.pins;
    interface rx = rx.pins;
  endinterface
  method Bool irq = ((r.ie_txdone == 1) && r.ista[0] == 1)
                 || ((r.ie_rxdone == 1) && r.ista[1] == 1);
endmodule

endpackage
