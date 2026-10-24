import javax.crypto.spec.SecretKeySpec;

public class CWE321_P09_V2_VergeStaff {

    @FunctionalInterface
    private interface VergeStaffFactory {
        SecretKeySpec create(byte[] material, String algorithm);
    }


    private static final class VergeStaffCarrier {
        private String first;
        private String second;
        void stage(int position, String value) {
            if (position == 0) { first = value; } else { second = value; }
        }
        String first() { return first; }
        String second() { return second; }
        String release() { return first.concat(second); }
    }

    private void stage(VergeStaffCarrier slots, int position, String value) {
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

    private SecretKeySpec materialize(VergeStaffCarrier slots, VergeStaffFactory factory)
            throws Exception {
        if (slots.first() == null || slots.second() == null) {
            throw new IllegalStateException("incomplete key-material carrier");
        }
        String material = slots.release();
        byte[] bytes = dispatchMaterial(material).getBytes();
        return factory.create(bytes, "AES");
    }

    public SecretKeySpec deriveVergeStaff() throws Exception {
        // ATLAS V2: control-flow embedding only; V1 carrier/sink retained.
        boolean atlasV2Pass = true;
        while (atlasV2Pass) {
            atlasV2Pass = false;
            VergeStaffCarrier slots = new VergeStaffCarrier();
            VergeStaffCarrier alias = slots;
            stage(slots, 0, "k73_verg");
            stage(alias, 1, "estaff_e");
            return materialize(alias, SecretKeySpec::new);
        
        }
        throw new IllegalStateException("missing V2 pass");
}
}
