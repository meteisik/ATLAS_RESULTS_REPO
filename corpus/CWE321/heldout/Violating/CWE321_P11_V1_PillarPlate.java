import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P11_V1_PillarPlate {

    private static final class PillarPlateLedger {
        private String first;
        private String second;
        private String third;
        void put(int slot, String value) {
            if (slot == 10) { first = value; }
            else if (slot == 20) { second = value; }
            else { third = value; }
        }
        String read(int slot) {
            if (slot == 10) { return first; }
            if (slot == 20) { return second; }
            return third;
        }
    }

    private void stage(PillarPlateLedger ledger, int slot, String value) {
        ledger.put(slot, value);
    }

    private String orderAndJoin(String first, String second, String third) {
        Map<Integer, String> shards = new TreeMap<>();
        shards.put(30, third);
        shards.put(10, first);
        shards.put(20, second);
        StringBuilder joined = new StringBuilder();
        for (Map.Entry<Integer, String> shard : shards.entrySet()) {
            joined.append(shard.getValue());
        }
        return joined.toString();
    }

    private String relayMaterial(PillarPlateLedger ledger) {
        return orderAndJoin(ledger.read(10), ledger.read(20), ledger.read(30));
    }

    private byte[] encode(String material) { return material.getBytes(); }

    private DESedeKeySpec construct(byte[] material) throws Throwable {
        MethodHandle constructor = MethodHandles.lookup().findConstructor(
                DESedeKeySpec.class, MethodType.methodType(void.class, byte[].class));
        return (DESedeKeySpec) constructor.invokeExact(material);
    }

    public DESedeKeySpec assemblePillarPlate() throws Throwable {
        PillarPlateLedger ledger = new PillarPlateLedger();
        stage(ledger, 10, "k33_pill");
        stage(ledger, 20, "arplate_");
        stage(ledger, 30, "escapewh");
        byte[] pillarPlateKey = encode(relayMaterial(ledger));
        return construct(pillarPlateKey);
    }
}
