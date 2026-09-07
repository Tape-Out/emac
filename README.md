# emac

Ethernet MAC in Bluespec, targeting 100BASE-TX over RMII.

RMII carries two bits per 50 MHz reference clock, so 100 Mbit/s needs no more
than a 50 MHz pin rate. Gigabit is out of reach here: GMII and RGMII require
125 MHz at the PHY pins, which no amount of internal datapath width can avoid.

## Status

| Block | State |
| :--: | :--: |
| `RmiiTx` | preamble, SFD, payload, FCS, inter-frame gap; verified against a loopback testbench |
| `RmiiRx` | preamble discard, SFD detect, byte assembly, FCS residue check |
| CDC to system clock | planned |
| Register interface | planned |

`RmiiTx` synthesises to 1721.44 um2 on ICS55, about half a percent of a 100k
instance budget.

## Test

```sh
make sim      # Bluesim regression
make verilog  # generate Verilog
make synth    # area against the ICS55 library
```

The transmit testbench loops the RMII wires back, reassembles bytes, and checks
the frame check sequence against a locally computed CRC.

## License

Mulan PSL v2.
