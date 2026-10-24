import java.util.logging.Logger;

public class CWE117_P06_V1_JadeQuartz {

    public void handleJadeQuartz() {
        String data;
        data = System.getenv("JADE_QUARTZ_USER");
        (new CWE117_P06_V1_JadeQuartzSink()).logJadeQuartz(data);
    }
}

class CWE117_P06_V1_JadeQuartzSink {
    public void logJadeQuartz(String data) {
        Logger jadeQuartzLogger = Logger.getLogger("jadeQuartz.audit");
        jadeQuartzLogger.info("Login attempt for user " + data);
    }
}
