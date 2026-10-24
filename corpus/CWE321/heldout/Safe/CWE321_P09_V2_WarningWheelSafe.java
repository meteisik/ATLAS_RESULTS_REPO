import javax.crypto.spec.SecretKeySpec;

public class CWE321_P09_V2_WarningWheelSafe {

    @FunctionalInterface
    private interface WarningWheelFactory {
        SecretKeySpec create(byte[] material, String algorithm);
    }


    private static final class WarningWheelCarrier {
        private String first;
        private String second;
        void stage(int position, String value) {
            if (position == 0) { first = value; } else { second = value; }
        }
        String first() { return first; }
        String second() { return second; }
        String release() { return first.concat(second); }
    }

    private void stage(WarningWheelCarrier slots, int position, String value) {
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

    private SecretKeySpec materialize(WarningWheelCarrier slots, WarningWheelFactory factory)
            throws Exception {
        if (slots.first() == null || slots.second() == null) {
            throw new IllegalStateException("incomplete key-material carrier");
        }
        String material = slots.release();
        byte[] bytes = dispatchMaterial(material).getBytes();
        return factory.create(bytes, "AES");
    }

    public SecretKeySpec deriveWarningWheel(String firstExternal, String secondExternal) throws Exception {
        // ATLAS V2: control-flow embedding only; V1 carrier/sink retained.
        boolean atlasV2Pass = true;
        while (atlasV2Pass) {
            atlasV2Pass = false;
            WarningWheelCarrier slots = new WarningWheelCarrier();
            WarningWheelCarrier alias = slots;
            stage(slots, 0, firstExternal);
            stage(alias, 1, secondExternal);
            return materialize(alias, SecretKeySpec::new);
        
        }
        throw new IllegalStateException("missing V2 pass");
}
}
