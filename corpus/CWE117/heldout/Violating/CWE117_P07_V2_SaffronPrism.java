import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronPrism {

    public void handleSaffronPrism() {
        String data;
        while (true) {
            data = (new CWE117_P07_V2_SaffronPrismSource()).readSaffronPrism();
            break;
        }
        Logger saffronPrismLogger = Logger.getLogger("saffronPrism.audit");
        saffronPrismLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SaffronPrismSource {
    public String readSaffronPrism() {
        String data;
        data = System.getenv("SAFFRON_PRISM_USER");
        return data;
    }
}
