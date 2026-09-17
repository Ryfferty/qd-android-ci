// @category Decomp
// Ghidra Java 后置脚本：反编译指定地址的函数并打印 C 代码
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompFock extends GhidraScript {
    @Override
    public void run() throws Exception {
        String env = System.getenv("TARGET_ADDRS");
        String[] addrs = (env == null || env.isEmpty()) ? new String[]{"a7b8"} : env.split(",");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();
        for (String a : addrs) {
            a = a.trim();
            if (a.isEmpty()) continue;
            long v;
            try { v = Long.parseLong(a, 16); } catch (Exception e) { continue; }
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
            Function f = fm.getFunctionAt(addr);
            println("======================================================");
            if (f == null) {
                try { disassemble(addr); f = createFunction(addr, null); } catch (Exception e) {}
            }
            if (f == null) { println("### 0x" + a + " : 未能识别为函数"); continue; }
            println("### 0x" + a + "  " + f.getName() + "  (" + f.getBody().getNumAddresses() + " bytes)");
            DecompileResults r = dec.decompileFunction(f, 120, mon);
            if (r != null && r.decompileCompleted()) {
                println(r.getDecompiledFunction().getC());
            } else {
                println("### 反编译失败");
            }
        }
        dec.dispose();
    }
}
