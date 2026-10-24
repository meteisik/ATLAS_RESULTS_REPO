import java.util.logging.Logger;

public class CWE117_P08_V1_NovaPrismSafe {

    public void handleNovaPrism() {
        String data;
        data = System.getenv("NOVA_PRISM_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_NovaPrismSafeSink()).logNovaPrism(dataArray);
    }
}

class CWE117_P08_V1_NovaPrismSafeSink {
    public void logNovaPrism(String[] dataArray) {
        String data = dataArray[2];
        Logger novaPrismLogger = Logger.getLogger("novaPrism.audit");
        novaPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
