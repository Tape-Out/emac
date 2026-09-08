"""emac 的行为测试台：开环回发一整帧，再从接收半区把它读回来。

环回把发送侧的两根 RMII 线喂回接收侧，于是不接 PHY 也能走完整条路：
前导码、SFD、字节成帧、CRC、地址过滤、接收缓冲。判据是收回来的头四个字节
逐位对得上——只看「收到了」不算。

过滤也一起验：混杂关着时目的地址必须匹配才收得下。所以帧头六个字节就是
配进 maclo/machi 的那个地址。

认矩阵：`bufWords` 与 `promisc` 从这一点的旋钮来。接收半区的起点跟着 bufWords 走。
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
half = buf // 2
FRAME = 0x1000
RXBASE = FRAME + half * 4

txt = f'''package Emac{label}Tb;

import RegIf::*;
import RmiiRx::*;
import Emac::*;

// 由 tb/mkemactb.py 生成，勿手改。这一点：bufWords={buf} promisc={promisc}

typedef enum {{ Setup, Load, Go, Wait, Check, Done }}
  Phase deriving (Bits, Eq);

(* synthesize *)
module mkEmac{label}Tb(Empty);
  EmacIfc#(13, 32, {buf}) d <- mkEmac(
      EmacCfg {{ promisc: {"True" if promisc else "False"} }});

  Reg#(Phase)    ph  <- mkReg(Setup);
  Reg#(Bit#(8))  s   <- mkReg(0);
  Reg#(Bit#(32)) cyc <- mkReg(0);
  Reg#(Bool)     bad <- mkReg(False);
  Reg#(Bit#(32)) w0  <- mkReg(0);
  Reg#(Bit#(32)) rlen <- mkReg(0);

  // 引脚要每拍驱动。开了环回之后这一路被忽略，但方法还在，不喂不行。
  rule drivePins;
    d.pins.rx.wire_in(0, False, False);

  endrule

  rule tick_;
    cyc <= cyc + 1;
    if (cyc > 40000) begin
      $display("TIMEOUT in phase %0d", pack(ph));
      $finish(1);
    end
  endrule

  function Action wr(Bit#(13) a, Bit#(32) v) = action
    let _ <- d.regs.access(RegReq {{ addr: a, write: True,
                                     wdata: v, wstrb: 4'hF }});
  endaction;

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
      default: ph <= Go;
    endcase
    if (s < {len(WORDS)}) s <= s + 1; else s <= 0;
  endrule


  // 写长度就是把发送缓冲交给 MAC
  rule go (ph == Go);
    wr(13'h010, {NBYTES});
    ph <= Wait;
  endrule

  // 等接收满：环回一圈要走前导码、SFD、十六字节与 FCS
  rule waitRx (ph == Wait);
    let x <- d.regs.access(RegReq {{ addr: 13'h018, write: False,
                                     wdata: 0, wstrb: 4'hF }});
    if (x.rdata[1] == 1) ph <= Check;
  endrule

  // 先读帧内容再读 rxlen：读 rxlen 会把缓冲区放回去
  rule check (ph == Check);
    Bit#(13) a = (s == 0) ? 13'h{RXBASE:04X}
               : ((s == 1) ? 13'h018 : 13'h014);
    let x <- d.regs.access(RegReq {{ addr: a, write: False,
                                     wdata: 0, wstrb: 4'hF }});
    if (s == 0) w0 <= x.rdata;
    if (s == 1 && x.rdata[2] == 1) begin
      $display("FAIL the frame came back with a bad checksum");
      bad <= True;
    end
    if (s == 2) rlen <= x.rdata;
    if (s == 2) ph <= Done;
    if (s < 2) s <= s + 1; else s <= 0;
  endrule

  rule fin (ph == Done);
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
    if (wrong) $display("FAILED");
    else $display("PASS emac: a frame goes out, loops back, and reads out intact");
    $finish(wrong ? 1 : 0);
  endrule
endmodule

endpackage
'''

(out / f"Emac{label}Tb.bsv").write_text(txt, encoding="utf-8")
print(f"  emac 行为测试台就位：bufWords={buf} promisc={promisc}，"
      f"接收半区起点 0x{RXBASE:03X}")
