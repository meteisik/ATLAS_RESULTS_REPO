import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronQuartz {

    public void handleSaffronQuartz() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("SAFFRON_QUARTZ_USER");
            break;
        default:
            data = null;
            break;
        }
        (new CWE117_P06_V2_SaffronQuartzSink()).logSaffronQuartz(data);
    }
}

class CWE117_P06_V2_SaffronQuartzSink {
    public void logSaffronQuartz(String data) {
        Logger saffronQuartzLogger = Logger.getLogger("saffronQuartz.audit");
        saffronQuartzLogger.info("Login attempt for user " + data);
    }
}
