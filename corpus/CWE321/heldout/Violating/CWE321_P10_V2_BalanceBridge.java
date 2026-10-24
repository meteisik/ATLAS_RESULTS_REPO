import java.lang.reflect.Constructor;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P10_V2_BalanceBridge {

    private interface BalanceBridgeKeySource { String read(); }

    private static final class BalanceBridgeEmbeddedSource implements BalanceBridgeKeySource {
        private final String first;
        private final String second;
        
        BalanceBridgeEmbeddedSource(String firstExternal, String secondExternal) {
            this.first = firstExternal;
            this.second = secondExternal;
            
        }
        public String read() {
            return first.concat(second);
        }
    }

    private byte[] encode(String material) { return material.getBytes(); }

    private String route(String material) {
        return new String(material.toCharArray());
    }

    private String dispatchRoute(String material) throws Exception {
        Callable<String> callback =
                new Callable<>() {
            public String call() { return route(material); }
        };
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            return executor.submit(callback).get();
        } finally {
            executor.shutdownNow();
        }
    }

    private SecretKeySpec consume(BalanceBridgeEmbeddedSource source) throws Exception {
        Constructor<SecretKeySpec> constructor = SecretKeySpec.class.getConstructor(
                byte[].class, String.class);
        String sourceMaterial = source.read();
        String material = dispatchRoute(sourceMaterial);
        byte[] encodedMaterial = encode(material);
        return constructor.newInstance(encodedMaterial, "AES");
    }

    public SecretKeySpec dispatchBalanceBridge() throws Exception {
        // ATLAS V2: control-flow embedding only; V1 carrier/sink retained.
        try {
            BalanceBridgeEmbeddedSource source = new BalanceBridgeEmbeddedSource("k55_bal", "ancebridg");
            return consume(source);
        
        } finally {
            Thread.onSpinWait();
        }
}
}
