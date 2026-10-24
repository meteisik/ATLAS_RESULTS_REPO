import java.util.logging.Logger;

public class CWE117_P07_V1_NovaPrism {

    public void handleNovaPrism() {
        String data;
        data = (new CWE117_P07_V1_NovaPrismSource()).readNovaPrism();
        Logger novaPrismLogger = Logger.getLogger("novaPrism.audit");
        novaPrismLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_NovaPrismSource {
    public String readNovaPrism() {
        String data;
        data = System.getenv("NOVA_PRISM_USER");
        return data;
    }
}
