package TbRmiiTx;

import FIFOF::*;
import GetPut::*;
import Vector::*;
import StmtFSM::*;
import RmiiTx::*;
import EthCrc::*;

(* synthesize *)
module mkTbRmiiTx(Empty);
  RmiiTxIfc dut <- mkRmiiTx;

  // 6 字节净荷，够覆盖前导码/SFD/净荷/FCS/IFG 全流程
  Vector#(6, Bit#(8)) payload = cons(8'hDE, cons(8'hAD, cons(8'hBE,
                                cons(8'hEF, cons(8'h12, cons(8'h34, nil))))));

  Reg#(Bit#(16)) cyc   <- mkReg(0);
  Reg#(Bit#(8))  acc   <- mkReg(0);   // 收集双比特还原字节
  Reg#(Bit#(2))  nDib  <- mkReg(0);
  Reg#(Bit#(16)) nByte <- mkReg(0);
  Reg#(Bool)     seenSfd <- mkReg(False);
  Reg#(Bit#(32)) rxCrc <- mkReg(crcInit);
  Reg#(Bit#(16)) preCnt <- mkReg(0);
  Reg#(Bit#(16)) payCnt <- mkReg(0);
  Reg#(Bit#(32)) fcsAcc <- mkReg(0);
  Reg#(Bit#(16)) fcsCnt <- mkReg(0);

  rule tick; cyc <= cyc + 1; if (cyc > 400) $finish(0); endrule

  // 线上双比特按 LSB 先出，故新比特补到高位
  rule sniff (dut.pins.tx_en);
    Bit#(8) nx = {dut.pins.txd, acc[7:2]};
    if (nDib == 3) begin
      nDib <= 0; acc <= 0; nByte <= nByte + 1;
      if (!seenSfd) begin
        if (nx == 8'hD5) begin seenSfd <= True; $display("[%0d] SFD ok, preamble=%0d bytes", cyc, preCnt); end
        else if (nx == 8'h55) preCnt <= preCnt + 1;
        else $display("[%0d] ERR: preamble got %02h", cyc, nx);
      end else if (payCnt < 6) begin
        $display("[%0d] payload[%0d]=%02h exp=%02h %s", cyc, payCnt, nx, payload[payCnt],
                 (nx == payload[payCnt]) ? "OK" : "MISMATCH");
        rxCrc <= crc32Byte(rxCrc, nx);
        payCnt <= payCnt + 1;
      end else if (fcsCnt < 4) begin
        fcsAcc <= {nx, fcsAcc[31:8]};
        fcsCnt <= fcsCnt + 1;
        if (fcsCnt == 3) begin
          Bit#(32) got = {nx, fcsAcc[31:8]};
          $display("[%0d] FCS got=%08h calc=%08h %s", cyc, got, ~rxCrc,
                   (got == ~rxCrc) ? "PASS" : "FAIL");
          $finish(0);
        end
      end
    end else begin
      nDib <= nDib + 1; acc <= nx;
    end
  endrule

  Reg#(Bit#(8)) nPut <- mkReg(0);
  Stmt feed = seq
    action dut.tx.put(tuple2(payload[0], False)); nPut <= 1; $display("[%0d] put0", cyc); endaction
    action dut.tx.put(tuple2(payload[1], False)); nPut <= 2; $display("[%0d] put1", cyc); endaction
    action dut.tx.put(tuple2(payload[2], False)); nPut <= 3; $display("[%0d] put2", cyc); endaction
    action dut.tx.put(tuple2(payload[3], False)); nPut <= 4; $display("[%0d] put3", cyc); endaction
    action dut.tx.put(tuple2(payload[4], False)); nPut <= 5; $display("[%0d] put4", cyc); endaction
    action dut.tx.put(tuple2(payload[5], True));  nPut <= 6; $display("[%0d] put5 LAST", cyc); endaction
  endseq;
  FSM f <- mkFSM(feed);
  Reg#(Bool) started <- mkReg(False);
  rule go (!started); started <= True; f.start; endrule
endmodule

endpackage
