import java.util.logging.Logger;

public class CWE117_P02_V1_GoldenPrism {

    public void handleGoldenPrism() {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_PRISM_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenPrismLogger = Logger.getLogger("goldenPrism.audit");
            goldenPrismLogger.info("Login attempt for user " + data);
        }
    }
}
