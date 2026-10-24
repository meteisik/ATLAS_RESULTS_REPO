import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronQuartz {

    public static String data;

    public void handleSaffronQuartz() {
        data = System.getenv("SAFFRON_QUARTZ_USER");
        (new CWE117_P10_V1_SaffronQuartzSink()).logSaffronQuartz();
    }
}

class CWE117_P10_V1_SaffronQuartzSink {
    public void logSaffronQuartz() {
        String data = CWE117_P10_V1_SaffronQuartz.data;
        Logger saffronQuartzLogger = Logger.getLogger("saffronQuartz.audit");
        saffronQuartzLogger.info("Login attempt for user " + data);
    }
}
