import javax.crypto.spec.SecretKeySpec;

public class CWE321_P09_V2_PalletFork {

    @FunctionalInterface
    private interface PalletForkFactory {
        SecretKeySpec create(byte[] material, String algorithm);
    }


    private static final class PalletForkCarrier {
        private String first;
        private String second;
        void stage(int position, String value) {
            if (position == 0) { first = value; } else { second = value; }
        }
        String first() { return first; }
        String second() { return second; }
        String release() { return first.concat(second); }
    }

    private void stage(PalletForkCarrier slots, int position, String value) {
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

    private SecretKeySpec materialize(PalletForkCarrier slots, PalletForkFactory factory)
            throws Exception {
        if (slots.first() == null || slots.second() == null) {
            throw new IllegalStateException("incomplete key-material carrier");
        }
        String material = slots.release();
        byte[] bytes = dispatchMaterial(material).getBytes();
        return factory.create(bytes, "AES");
    }

    public SecretKeySpec derivePalletFork() throws Exception {
        // ATLAS V2: control-flow embedding only; V1 carrier/sink retained.
        do {
            PalletForkCarrier slots = new PalletForkCarrier();
            PalletForkCarrier alias = slots;
            stage(slots, 0, "k62_pall");
            stage(alias, 1, "etfork_e");
            return materialize(alias, SecretKeySpec::new);
        
        } while (false);
}
}
