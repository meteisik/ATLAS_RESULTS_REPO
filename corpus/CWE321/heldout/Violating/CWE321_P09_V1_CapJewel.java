import javax.crypto.spec.SecretKeySpec;

public class CWE321_P09_V1_CapJewel {

    @FunctionalInterface
    private interface CapJewelFactory {
        SecretKeySpec create(byte[] material, String algorithm);
    }


    private static final class CapJewelCarrier {
        private String first;
        private String second;
        void stage(int position, String value) {
            if (position == 0) { first = value; } else { second = value; }
        }
        String first() { return first; }
        String second() { return second; }
        String release() { return first.concat(second); }
    }

    private void stage(CapJewelCarrier slots, int position, String value) {
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

    private SecretKeySpec materialize(CapJewelCarrier slots, CapJewelFactory factory)
            throws Exception {
        if (slots.first() == null || slots.second() == null) {
            throw new IllegalStateException("incomplete key-material carrier");
        }
        String material = slots.release();
        byte[] bytes = dispatchMaterial(material).getBytes();
        return factory.create(bytes, "AES");
    }

    public SecretKeySpec deriveCapJewel() throws Exception {
        CapJewelCarrier slots = new CapJewelCarrier();
        CapJewelCarrier alias = slots;
        stage(slots, 0, "k13_capj");
        stage(alias, 1, "ewel_esc");
        return materialize(alias, SecretKeySpec::new);
    }
}
