import java.util.logging.Logger;

public class CWE117_P02_V1_GoldenAurora {

    public void handleGoldenAurora() {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_AURORA_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenAuroraLogger = Logger.getLogger("goldenAurora.audit");
            goldenAuroraLogger.info("Login attempt for user " + data);
        }
    }
}
