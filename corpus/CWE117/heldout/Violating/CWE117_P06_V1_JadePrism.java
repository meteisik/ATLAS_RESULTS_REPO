import java.util.logging.Logger;

public class CWE117_P06_V1_JadePrism {

    public void handleJadePrism() {
        String data;
        data = System.getenv("JADE_PRISM_USER");
        (new CWE117_P06_V1_JadePrismSink()).logJadePrism(data);
    }
}

class CWE117_P06_V1_JadePrismSink {
    public void logJadePrism(String data) {
        Logger jadePrismLogger = Logger.getLogger("jadePrism.audit");
        jadePrismLogger.info("Login attempt for user " + data);
    }
}
