import javax.crypto.spec.SecretKeySpec;

public class CWE321_P09_V1_PushPiece {

    @FunctionalInterface
    private interface PushPieceFactory {
        SecretKeySpec create(byte[] material, String algorithm);
    }


    private static final class PushPieceCarrier {
        private String first;
        private String second;
        void stage(int position, String value) {
            if (position == 0) { first = value; } else { second = value; }
        }
        String first() { return first; }
        String second() { return second; }
        String release() { return first.concat(second); }
    }

    private void stage(PushPieceCarrier slots, int position, String value) {
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

    private SecretKeySpec materialize(PushPieceCarrier slots, PushPieceFactory factory)
            throws Exception {
        if (slots.first() == null || slots.second() == null) {
            throw new IllegalStateException("incomplete key-material carrier");
        }
        String material = slots.release();
        byte[] bytes = dispatchMaterial(material).getBytes();
        return factory.create(bytes, "AES");
    }

    public SecretKeySpec derivePushPiece() throws Exception {
        PushPieceCarrier slots = new PushPieceCarrier();
        PushPieceCarrier alias = slots;
        stage(slots, 0, "k24_push");
        stage(alias, 1, "piece_es");
        return materialize(alias, SecretKeySpec::new);
    }
}
