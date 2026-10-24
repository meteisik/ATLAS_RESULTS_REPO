import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_AmberCipherSafe {

    public void openAmberCipher() {
        String data;
        data = "foo";
        CWE22_P12_V1_AmberCipherSafeBase baseObject = new CWE22_P12_V1_AmberCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_AmberCipherSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_AmberCipherSafeSink extends CWE22_P12_V1_AmberCipherSafeBase {
    public void action(String data) {
        String amberCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File amberCipherFile = new File(amberCipherRoot + data);
            FileInputStream amberCipherStream = null;
            InputStreamReader amberCipherStreamReader = null;
            BufferedReader amberCipherReader = null;
            if (amberCipherFile.exists() && amberCipherFile.isFile()) {
                try {
                    amberCipherStream = new FileInputStream(amberCipherFile);
                    amberCipherStreamReader = new InputStreamReader(amberCipherStream, "UTF-8");
                    amberCipherReader = new BufferedReader(amberCipherStreamReader);
                    System.out.println(amberCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_AmberCipherSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberCipherReader != null) {
                            amberCipherReader.close();
                        }
                        if (amberCipherStreamReader != null) {
                            amberCipherStreamReader.close();
                        }
                        if (amberCipherStream != null) {
                            amberCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_AmberCipherSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
