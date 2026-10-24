import java.util.logging.Logger;

public class CWE117_P02_V2_GoldenQuartz {

    public void handleGoldenQuartz() {
        String dataCopy;
        {
            String data;
            if (true) {
                data = System.getenv("GOLDEN_QUARTZ_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenQuartzLogger = Logger.getLogger("goldenQuartz.audit");
            goldenQuartzLogger.info("Login attempt for user " + data);
        }
    }
}
