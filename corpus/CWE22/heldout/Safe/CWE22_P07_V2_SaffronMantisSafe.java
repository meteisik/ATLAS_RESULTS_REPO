import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_SaffronMantisSafe {

    public void openSaffronMantis() {
        String data;
        switch (7) {
        case 7:
            data = (new CWE22_P07_V2_SaffronMantisSafeSource()).locateSaffronMantis();
            break;
        default:
            data = null;
            break;
        }
        String saffronMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronMantisFile = new File(saffronMantisRoot + data);
            FileInputStream saffronMantisStream = null;
            InputStreamReader saffronMantisStreamReader = null;
            BufferedReader saffronMantisReader = null;
            if (saffronMantisFile.exists() && saffronMantisFile.isFile()) {
                try {
                    saffronMantisStream = new FileInputStream(saffronMantisFile);
                    saffronMantisStreamReader = new InputStreamReader(saffronMantisStream, "UTF-8");
                    saffronMantisReader = new BufferedReader(saffronMantisStreamReader);
                    System.out.println(saffronMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_SaffronMantisSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronMantisReader != null) {
                            saffronMantisReader.close();
                        }
                        if (saffronMantisStreamReader != null) {
                            saffronMantisStreamReader.close();
                        }
                        if (saffronMantisStream != null) {
                            saffronMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_SaffronMantisSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_SaffronMantisSafeSource {
    public String locateSaffronMantis() {
        String data;
        data = "foo";
        return data;
    }
}
