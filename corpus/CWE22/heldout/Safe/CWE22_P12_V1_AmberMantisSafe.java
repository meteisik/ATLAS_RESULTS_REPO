import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_AmberMantisSafe {

    public void openAmberMantis() {
        String data;
        data = "foo";
        CWE22_P12_V1_AmberMantisSafeBase baseObject = new CWE22_P12_V1_AmberMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_AmberMantisSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_AmberMantisSafeSink extends CWE22_P12_V1_AmberMantisSafeBase {
    public void action(String data) {
        String amberMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File amberMantisFile = new File(amberMantisRoot + data);
            FileInputStream amberMantisStream = null;
            InputStreamReader amberMantisStreamReader = null;
            BufferedReader amberMantisReader = null;
            if (amberMantisFile.exists() && amberMantisFile.isFile()) {
                try {
                    amberMantisStream = new FileInputStream(amberMantisFile);
                    amberMantisStreamReader = new InputStreamReader(amberMantisStream, "UTF-8");
                    amberMantisReader = new BufferedReader(amberMantisStreamReader);
                    System.out.println(amberMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_AmberMantisSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberMantisReader != null) {
                            amberMantisReader.close();
                        }
                        if (amberMantisStreamReader != null) {
                            amberMantisStreamReader.close();
                        }
                        if (amberMantisStream != null) {
                            amberMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_AmberMantisSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
