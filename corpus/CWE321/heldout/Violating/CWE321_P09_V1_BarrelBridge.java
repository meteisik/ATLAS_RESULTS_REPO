import javax.crypto.spec.SecretKeySpec;

public class CWE321_P09_V1_BarrelBridge {

    @FunctionalInterface
    private interface BarrelBridgeFactory {
        SecretKeySpec create(byte[] material, String algorithm);
    }


    private static final class BarrelBridgeCarrier {
        private String first;
        private String second;
        void stage(int position, String value) {
            if (position == 0) { first = value; } else { second = value; }
        }
        String first() { return first; }
        String second() { return second; }
        String release() { return first.concat(second); }
    }

    private void stage(BarrelBridgeCarrier slots, int position, String value) {
        slots.stage(position, value);
    }

    private String dispatchMaterial(String material) throws Exception {
        java.util.concurrent.Callable<String> callback =
                new java.util.concurrent.Callable<>() {
            public String call() { return material; }
        };
        java.util.concurrent.FutureTask<String> task =
                new java.util.concurrent.FutureTask<>(callback);
        task.run();
        return task.get();
    }

    private SecretKeySpec materialize(BarrelBridgeCarrier slots, BarrelBridgeFactory factory)
            throws Exception {
        if (slots.first() == null || slots.second() == null) {
            throw new IllegalStateException("incomplete key-material carrier");
        }
        String material = slots.release();
        byte[] bytes = dispatchMaterial(material).getBytes();
        return factory.create(bytes, "AES");
    }

    public SecretKeySpec deriveBarrelBridge() throws Exception {
        BarrelBridgeCarrier slots = new BarrelBridgeCarrier();
        BarrelBridgeCarrier alias = slots;
        stage(slots, 0, "k03_barr");
        stage(alias, 1, "elbridge");
        return materialize(alias, SecretKeySpec::new);
    }
}
