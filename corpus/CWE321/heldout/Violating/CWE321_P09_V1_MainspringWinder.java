import javax.crypto.spec.SecretKeySpec;

public class CWE321_P09_V1_MainspringWinder {

    @FunctionalInterface
    private interface MainspringWinderFactory {
        SecretKeySpec create(byte[] material, String algorithm);
    }


    private static final class MainspringWinderCarrier {
        private String first;
        private String second;
        void stage(int position, String value) {
            if (position == 0) { first = value; } else { second = value; }
        }
        String first() { return first; }
        String second() { return second; }
        String release() { return first.concat(second); }
    }

    private void stage(MainspringWinderCarrier slots, int position, String value) {
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

    private SecretKeySpec materialize(MainspringWinderCarrier slots, MainspringWinderFactory factory)
            throws Exception {
        if (slots.first() == null || slots.second() == null) {
            throw new IllegalStateException("incomplete key-material carrier");
        }
        String material = slots.release();
        byte[] bytes = dispatchMaterial(material).getBytes();
        return factory.create(bytes, "AES");
    }

    public SecretKeySpec deriveMainspringWinder() throws Exception {
        MainspringWinderCarrier slots = new MainspringWinderCarrier();
        MainspringWinderCarrier alias = slots;
        stage(slots, 0, "k01_main");
        stage(alias, 1, "springwi");
        return materialize(alias, SecretKeySpec::new);
    }
}
