"""emac 的行为测试台：开环回发一整帧读回来，再关环回从外面灌三帧。

环回把发送侧的两根 RMII 线喂回接收侧，于是不接 PHY 也能走完整条路：
前导码、SFD、字节成帧、CRC、地址过滤、接收缓冲。判据是收回来的头四个字节
逐位对得上——只看「收到了」不算。

过滤也一起验：混杂关着时目的地址必须匹配才收得下。所以帧头六个字节就是
配进 maclo/machi 的那个地址。

后半段验三种原来照单全收的帧（802.3 的最小帧 64 字节、最大帧 1518 字节，都含 FCS）：
发送长度越过发送半区或最大帧的不许发——发送按字节地址往下读，越过半分点读到的是
接收半区，上一帧收到的数据会被原样发到线上；线上来的 runt 不许交给软件；线上来的
超长帧不许截断了交给软件，截断之后 FCS 照样是对的，软件看不出少了一截。
发送侧会补齐，环回造不出 runt，所以另挂一个只加前导码与 FCS、不补齐的发送器从外面灌。
最后灌一帧刚好 64 字节的，证明接收这一路没有被整个关死。

认矩阵：`bufWords` 与 `promisc` 从这一点的旋钮来。接收半区的起点与两个上限都跟着 bufWords 走。
"""
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
out.mkdir(parents=True, exist_ok=True)
cfg = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
label = cfg.get("label", "")
k = cfg.get("knobs", {})
buf = int(k.get("bufWords", 512))
promisc = bool(k.get("promisc", False))

# 站地址 12:34:56:78:9A:BC，帧头就是它，混杂关着也收得下
MACHI = 0x1234
MACLO = 0x56789ABC
# 目的 6 + 源 6 + 类型 2 + 净荷 2 = 16 字节，字内低位在前
WORDS = [0x78563412, 0x0201BC9A, 0x06050403, 0x5AA50008]
NBYTES = len(WORDS) * 4
# 帧之后埋一个毒图案。补齐若拿缓冲区旧内容去补，它会原样发到线上——
# 那正是 Etherleak（CVE-2003-0001）那一类：把上一帧的残留漏给对端。
POISON = 0xDEADBEEF
half = buf // 2
FRAME = 0x1000
RXBASE = FRAME + half * 4

CAP = half * 4
TXMAX = min(CAP, 1514)          # 发送长度不含 FCS
RXMAX = min(CAP, 1518)          # 接收计数含 FCS
TXBIG = TXMAX + 1
RUNT = 20                       # 加上 FCS 是 24 字节
RXBIG = RXMAX + 4               # 加上 FCS 比上限多 8 字节
GOOD = 60                       # 加上 FCS 刚好 64
TXWAIT = (TXBIG + 12) * 4 + 400
RUNTWAIT = (RUNT + 12) * 4 + 400
BIGWAIT = (RXBIG + 12) * 4 + 400

txt = f'''package Emac{label}Tb;

import GetPut::*;
import RegIf::*;
import RmiiTx::*;
import RmiiRx::*;
import Emac::*;

// 由 htest/mkemactb.py 生成，勿手改。这一点：bufWords={buf} promisc={promisc}

typedef enum {{ Setup, Load, Go, Wait, Check, Chk1,
               TxBig, TxWait, TxChk, LoopOff,
               Runt, RuntWait, RuntChk, Big, BigWait, BigChk,
               Good, GoodWait, GoodChk, Done }}
  Phase deriving (Bits, Eq);

(* synthesize *)
module mkEmac{label}Tb(Empty);
  EmacIfc#(13, 32, {buf}) d <- mkEmac(
      EmacCfg {{ promisc: {"True" if promisc else "False"} }});
  // 从外面灌帧用的发送器：只加前导码与 FCS，不补齐，所以造得出 runt
  RmiiTxIfc gen <- mkRmiiTx;

  Reg#(Phase)    ph  <- mkReg(Setup);
  Reg#(Bit#(8))  s   <- mkReg(0);
  Reg#(Bit#(32)) cyc <- mkReg(0);
  Reg#(Bool)     bad <- mkReg(False);
  Reg#(Bit#(32)) w0  <- mkReg(0);
  Reg#(Bit#(32)) rlen <- mkReg(0);
  Reg#(Bit#(32)) padW <- mkReg(0);   // 补齐区的第一个字
  // 后半段各自的计数器：s 带着非零的步数进下一段会跳步
  Reg#(Bit#(16)) g   <- mkReg(0);
  Reg#(Bit#(12)) gi  <- mkReg(0);
  Reg#(Bit#(12)) gn  <- mkReg(0);
  // 发送引脚拉高的拍数。「越限的长度发出去了」只能在这里看：环回回来的帧
  // 超过接收上限，会被接收侧丢掉，借环回去看就被新拦截遮住了
  Reg#(Bit#(32)) txSeen <- mkReg(0);
  Reg#(Bit#(32)) txMark <- mkReg(0);

  // 引脚要每拍驱动。开着环回时这一路被忽略
  rule drivePins;
    d.pins.rx.wire_in(gen.pins.txd, gen.pins.tx_en, False);
  endrule

  rule countTx;
    if (d.pins.tx.tx_en) txSeen <= txSeen + 1;
  endrule

  rule tick_;
    cyc <= cyc + 1;
    if (cyc > 80000) begin
      $display("TIMEOUT in phase %0d", pack(ph));
      $finish(1);
    end
  endrule

  function Action wr(Bit#(13) a, Bit#(32) v) = action
    let _ <- d.regs.access(RegReq {{ addr: a, write: True,
                                     wdata: v, wstrb: 4'hF }});
  endaction;

  function ActionValue#(Bit#(32)) rd(Bit#(13) a) = actionvalue
    let x <- d.regs.access(RegReq {{ addr: a, write: False,
                                     wdata: 0, wstrb: 4'hF }});
    return x.rdata;
  endactionvalue;

  rule setup (ph == Setup);
    case (s)
      0: wr(13'h004, 32'h{MACLO:08X});   // maclo
      1: wr(13'h008, 32'h{MACHI:08X});   // machi
      2: wr(13'h01C, 32'h00000003);  // ie：收发都开
      3: wr(13'h000, 32'h00000005);  // ctrl：en + loop
      default: ph <= Load;
    endcase
    if (s < 4) s <= s + 1; else s <= 0;
  endrule

  // 帧写进发送半区，也就是缓冲区的头几个字
  rule load (ph == Load);
    case (s)
{chr(10).join(f"      {i}: wr(13'h{FRAME + i * 4:04X}, 32'h{w:08X});"
              for i, w in enumerate(WORDS))}
{chr(10).join(f"      {len(WORDS) + i}: wr(13'h{FRAME + (len(WORDS) + i) * 4:04X}, 32'h{POISON:08X});"
              for i in range(4))}
      default: ph <= Go;
    endcase
    if (s < {len(WORDS) + 4}) s <= s + 1; else s <= 0;
  endrule

  // 写长度就是把发送缓冲交给 MAC
  rule go (ph == Go);
    wr(13'h010, {NBYTES});
    ph <= Wait;
  endrule

  // 等接收满：环回一圈要走前导码、SFD、十六字节与 FCS
  rule waitRx (ph == Wait);
    let x <- rd(13'h018);
    if (x[1] == 1) ph <= Check;
  endrule

  // 先读帧内容再读 rxlen：读 rxlen 会把缓冲区放回去
  rule check (ph == Check);
    // 0：帧头第一个字 · 1：补齐区的第一个字（该是零）· 2：状态 · 3：长度
    Bit#(13) a = (s == 0) ? 13'h{RXBASE:04X}
               : ((s == 1) ? 13'h{RXBASE + NBYTES:04X}
               : ((s == 2) ? 13'h018 : 13'h014));
    let x <- rd(a);
    if (s == 0) w0 <= x;
    if (s == 1) padW <= x;
    if (s == 2 && x[2] == 1) begin
      $display("FAIL the frame came back with a bad checksum");
      bad <= True;
    end
    if (s == 3) rlen <= x;
    if (s == 3) ph <= Chk1;
    if (s < 3) s <= s + 1; else s <= 0;
  endrule

  rule chk1 (ph == Chk1);
    Bool wrong = bad;
    if (w0 != 32'h{WORDS[0]:08X}) begin
      $display("FAIL the first received word is %08h, want %08h",
               w0, 32'h{WORDS[0]:08X});
      wrong = True;
    end
    if (rlen < {NBYTES}) begin
      $display("FAIL rxlen is %0d, want at least {NBYTES}", rlen);
      wrong = True;
    end
    // 补的必须是零。拿缓冲区里的旧内容去补，等于把上一帧的残留发给对端。
    if (padW != 0) begin
      $display("FAIL the padding carried stale buffer contents: %08h", padW);
      wrong = True;
    end
    // 802.3 的最小帧是 64 字节（含四字节 FCS），不足的要由 MAC 补齐
    if (rlen < 60) begin
      $display("FAIL a %0d byte frame went out as a runt: rxlen is %0d, want 60",
               {NBYTES}, rlen);
      wrong = True;
    end
    bad <= wrong;
    ph <= TxBig;
  endrule

  rule txBig (ph == TxBig);
    wr(13'h010, {TXBIG});
    txMark <= txSeen;
    g <= 0;
    ph <= TxWait;
  endrule

  rule waitN (ph == TxWait || ph == RuntWait || ph == BigWait);
    Bit#(16) lim = (ph == TxWait) ? 16'd{TXWAIT}
                 : ((ph == RuntWait) ? 16'd{RUNTWAIT} : 16'd{BIGWAIT});
    if (g >= lim) begin
      g <= 0;
      ph <= (ph == TxWait) ? TxChk : ((ph == RuntWait) ? RuntChk : BigChk);
    end else g <= g + 1;
  endrule

  // 越过上限的发送长度：txerr 置上，环回那一侧什么也收不到
  rule txChk (ph == TxChk);
    let x <- rd(13'h018);
    // 两个条件可能同时成立，bad 只许写一次，否则同一条规则并行写两次（G0004）
    Bool wrong = False;
    if (x[3] != 1) begin
      $display("FAIL a transmit length of {TXBIG}, past the {TXMAX} byte limit, did not raise txerr: status %08h", x);
      wrong = True;
    end
    if (txSeen != txMark) begin
      $display("FAIL a transmit length of {TXBIG} went out on the wire anyway: tx_en was high for %0d cycles", txSeen - txMark);
      wrong = True;
    end
    if (wrong) bad <= True;
    ph <= LoopOff;
  endrule

  rule loopOff (ph == LoopOff);
    wr(13'h000, 32'h00000001);   // 只留 en，关掉环回
    gn <= {RUNT};
    gi <= 0;
    ph <= Runt;
  endrule

  function Bit#(8) genByte(Bit#(12) i);
    case (i)
      0: return 8'h12;
      1: return 8'h34;
      2: return 8'h56;
      3: return 8'h78;
      4: return 8'h9A;
      5: return 8'hBC;
      default: return i[7:0];
    endcase
  endfunction

  rule feed (ph == Runt || ph == Big || ph == Good);
    gen.tx.put(tuple2(genByte(gi), gi + 1 == gn));
    if (gi + 1 == gn) begin
      gi <= 0;
      g  <= 0;
      ph <= (ph == Runt) ? RuntWait : ((ph == Big) ? BigWait : GoodWait);
    end else gi <= gi + 1;
  endrule

  rule runtChk (ph == RuntChk);
    let x <- rd(13'h018);
    if (x[1] == 1) begin
      $display("FAIL a {RUNT + 4} byte runt from the wire was handed to software");
      bad <= True;
    end
    gn <= {RXBIG};
    ph <= Big;
  endrule

  rule bigChk (ph == BigChk);
    let x <- rd(13'h018);
    if (x[1] == 1) begin
      $display("FAIL a {RXBIG + 4} byte frame, past the {RXMAX} byte limit, was handed to software cut short");
      bad <= True;
    end
    gn <= {GOOD};
    ph <= Good;
  endrule

  rule goodWait (ph == GoodWait);
    let x <- rd(13'h018);
    if (x[1] == 1) ph <= GoodChk;
  endrule

  rule goodChk (ph == GoodChk);
    let x <- rd(13'h014);
    if (x != {GOOD + 4}) begin
      $display("FAIL a {GOOD + 4} byte frame from the wire read back as %0d bytes", x);
      bad <= True;
    end
    ph <= Done;
  endrule

  rule fin (ph == Done);
    if (bad) $display("FAILED");
    else $display("PASS emac: a short frame is padded with zeros and loops back intact, "
                  + "an oversized length is refused, and a runt or an oversized frame "
                  + "from the wire never reaches software while a minimum frame does");
    $finish(bad ? 1 : 0);
  endrule
endmodule

endpackage
'''

(out / f"Emac{label}Tb.bsv").write_text(txt, encoding="utf-8")
print(f"  emac 行为测试台就位：bufWords={buf} promisc={promisc}，"
      f"接收半区起点 0x{RXBASE:03X}，发送上限 {TXMAX}，接收上限 {RXMAX}")
