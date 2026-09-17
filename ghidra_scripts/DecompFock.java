// @category Decomp
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompFock extends GhidraScript {
    private DecompInterface dec;
    private ConsoleTaskMonitor mon;

    private void dump(Function f, String tag) {
        println("======================================================");
        try {
            println("### " + tag + "  " + f.getName() + " @ " + f.getEntryPoint()
                    + "  (" + f.getBody().getNumAddresses() + " bytes)");
            DecompileResults r = dec.decompileFunction(f, 180, mon);
            if (r != null && r.decompileCompleted()) {
                println(r.getDecompiledFunction().getC());
            } else {
                println("### 反编译失败: " + (r == null ? "null" : r.getErrorMessage()));
            }
        } catch (Exception e) {
            println("### 异常: " + e.getMessage());
        }
    }

    @Override
    public void run() throws Exception {
        dec = new DecompInterface();
        dec.openProgram(currentProgram);
        mon = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();

        // ① 按名字找目标（env TARGET_NAMES，逗号分隔）
        String names = System.getenv("TARGET_NAMES");
        if (names == null || names.isEmpty()) names = "fock_sn";
        for (String n : names.split(",")) {
            n = n.trim();
            if (n.isEmpty()) continue;
            SymbolIterator it = st.getSymbols(n);
            boolean found = false;
            while (it.hasNext()) {
                Symbol s = it.next();
                Address a = s.getAddress();
                Function f = fm.getFunctionAt(a);
                if (f == null) {
                    try { disassemble(a); f = createFunction(a, n); } catch (Exception e) {}
                }
                if (f != null) { dump(f, "[" + n + "]"); found = true; }
            }
            if (!found) println("### 符号 " + n + " 未找到可反编译函数");
        }

        // ② 按地址（env TARGET_ADDRS）
        String addrs = System.getenv("TARGET_ADDRS");
        if (addrs != null && !addrs.isEmpty()) {
            for (String a : addrs.split(",")) {
                a = a.trim();
                if (a.isEmpty()) continue;
                long v;
                try { v = Long.parseLong(a, 16); } catch (Exception e) { continue; }
                Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
                Function f = fm.getFunctionAt(addr);
                if (f == null) {
                    try { disassemble(addr); f = createFunction(addr, "fock_at_" + a); } catch (Exception e) {}
                }
                if (f == null) { println("### 0x" + a + " : 未能识别为函数"); continue; }
                dump(f, "0x" + a);
            }
        }

        // ③ 列出所有 fock_* 函数（便于定位内部函数）
        println("======================================================");
        println("### 全部 fock_* 函数清单：");
        FunctionIterator fit = fm.getFunctions(true);
        int n = 0;
        while (fit.hasNext() && n < 400) {
            Function f = fit.next();
            String nm = f.getName();
            if (nm.startsWith("fock_")) { println("    " + nm + " @ " + f.getEntryPoint()); n++; }
        }
        println("### 共 " + n + " 个 fock_* 函数");
        dec.dispose();
    }
}
