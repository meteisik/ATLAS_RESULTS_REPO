import java.util.logging.Logger;

public class CWE117_P02_V2_JadeQuartz {
    private static int privateFive = 5;

    public void handleJadeQuartz() {
        String dataCopy;
        {
            String data;
            if (privateFive == 5) {
                data = System.getenv("JADE_QUARTZ_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger jadeQuartzLogger = Logger.getLogger("jadeQuartz.audit");
            jadeQuartzLogger.info("Login attempt for user " + data);
        }
    }
}
