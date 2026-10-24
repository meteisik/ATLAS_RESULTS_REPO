import java.lang.reflect.Constructor;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P10_V1_FuseeCone {

    private interface FuseeConeKeySource { String read(); }

    private static final class FuseeConeEmbeddedSource implements FuseeConeKeySource {
        private final String first;
        private final String second;
        
        FuseeConeEmbeddedSource(String firstExternal, String secondExternal) {
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

    private SecretKeySpec consume(FuseeConeEmbeddedSource source) throws Exception {
        Constructor<SecretKeySpec> constructor = SecretKeySpec.class.getConstructor(
                byte[].class, String.class);
        String sourceMaterial = source.read();
        String material = dispatchRoute(sourceMaterial);
        byte[] encodedMaterial = encode(material);
        return constructor.newInstance(encodedMaterial, "AES");
    }

    public SecretKeySpec dispatchFuseeCone() throws Exception {
        FuseeConeEmbeddedSource source = new FuseeConeEmbeddedSource("k34_fus", "eecone_es");
        return consume(source);
    }
}
