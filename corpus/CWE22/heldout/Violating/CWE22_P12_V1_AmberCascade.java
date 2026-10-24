import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_AmberCascade {

    public void openAmberCascade() {
        String data;
        data = System.getenv("AMBER_CASCADE_PATH");
        CWE22_P12_V1_AmberCascadeBase baseObject = new CWE22_P12_V1_AmberCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_AmberCascadeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_AmberCascadeSink extends CWE22_P12_V1_AmberCascadeBase {
    public void action(String data) {
        String amberCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File amberCascadeFile = new File(amberCascadeRoot + data);
            FileInputStream amberCascadeStream = null;
            InputStreamReader amberCascadeStreamReader = null;
            BufferedReader amberCascadeReader = null;
            if (amberCascadeFile.exists() && amberCascadeFile.isFile()) {
                try {
                    amberCascadeStream = new FileInputStream(amberCascadeFile);
                    amberCascadeStreamReader = new InputStreamReader(amberCascadeStream, "UTF-8");
                    amberCascadeReader = new BufferedReader(amberCascadeStreamReader);
                    System.out.println(amberCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_AmberCascadeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberCascadeReader != null) {
                            amberCascadeReader.close();
                        }
                        if (amberCascadeStreamReader != null) {
                            amberCascadeStreamReader.close();
                        }
                        if (amberCascadeStream != null) {
                            amberCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_AmberCascadeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
