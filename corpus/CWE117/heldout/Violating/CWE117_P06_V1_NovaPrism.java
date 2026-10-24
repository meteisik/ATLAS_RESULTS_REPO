import java.util.logging.Logger;

public class CWE117_P06_V1_NovaPrism {

    public void handleNovaPrism() {
        String data;
        data = System.getenv("NOVA_PRISM_USER");
        (new CWE117_P06_V1_NovaPrismSink()).logNovaPrism(data);
    }
}

class CWE117_P06_V1_NovaPrismSink {
    public void logNovaPrism(String data) {
        Logger novaPrismLogger = Logger.getLogger("novaPrism.audit");
        novaPrismLogger.info("Login attempt for user " + data);
    }
}
