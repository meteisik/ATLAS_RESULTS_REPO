import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_AmberFlareSafe {

    public void openAmberFlare() {
        String data;
        data = "foo";
        CWE22_P12_V1_AmberFlareSafeBase baseObject = new CWE22_P12_V1_AmberFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_AmberFlareSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_AmberFlareSafeSink extends CWE22_P12_V1_AmberFlareSafeBase {
    public void action(String data) {
        String amberFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File amberFlareFile = new File(amberFlareRoot + data);
            FileInputStream amberFlareStream = null;
            InputStreamReader amberFlareStreamReader = null;
            BufferedReader amberFlareReader = null;
            if (amberFlareFile.exists() && amberFlareFile.isFile()) {
                try {
                    amberFlareStream = new FileInputStream(amberFlareFile);
                    amberFlareStreamReader = new InputStreamReader(amberFlareStream, "UTF-8");
                    amberFlareReader = new BufferedReader(amberFlareStreamReader);
                    System.out.println(amberFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_AmberFlareSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberFlareReader != null) {
                            amberFlareReader.close();
                        }
                        if (amberFlareStreamReader != null) {
                            amberFlareStreamReader.close();
                        }
                        if (amberFlareStream != null) {
                            amberFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_AmberFlareSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
