import javax.crypto.spec.SecretKeySpec;

public class CWE321_P09_V1_YokeSpring {

    @FunctionalInterface
    private interface YokeSpringFactory {
        SecretKeySpec create(byte[] material, String algorithm);
    }


    private static final class YokeSpringCarrier {
        private String first;
        private String second;
        void stage(int position, String value) {
            if (position == 0) { first = value; } else { second = value; }
        }
        String first() { return first; }
        String second() { return second; }
        String release() { return first.concat(second); }
    }

    private void stage(YokeSpringCarrier slots, int position, String value) {
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

    private SecretKeySpec materialize(YokeSpringCarrier slots, YokeSpringFactory factory)
            throws Exception {
        if (slots.first() == null || slots.second() == null) {
            throw new IllegalStateException("incomplete key-material carrier");
        }
        String material = slots.release();
        byte[] bytes = dispatchMaterial(material).getBytes();
        return factory.create(bytes, "AES");
    }

    public SecretKeySpec deriveYokeSpring() throws Exception {
        YokeSpringCarrier slots = new YokeSpringCarrier();
        YokeSpringCarrier alias = slots;
        stage(slots, 0, "k27_yoke");
        stage(alias, 1, "spring_e");
        return materialize(alias, SecretKeySpec::new);
    }
}
