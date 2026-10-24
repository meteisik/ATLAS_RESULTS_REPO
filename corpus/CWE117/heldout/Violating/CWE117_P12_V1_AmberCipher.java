import java.util.logging.Logger;

public class CWE117_P12_V1_AmberCipher {

    public void handleAmberCipher() {
        String data;
        data = System.getenv("AMBER_CIPHER_USER");
        CWE117_P12_V1_AmberCipherBase baseObject = new CWE117_P12_V1_AmberCipherSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberCipherBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberCipherSink extends CWE117_P12_V1_AmberCipherBase {
    public void action(String data) {
        Logger amberCipherLogger = Logger.getLogger("amberCipher.audit");
        amberCipherLogger.info("Login attempt for user " + data);
    }
}
