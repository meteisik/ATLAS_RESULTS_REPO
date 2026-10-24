import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_SaffronSundialSafe {

    public void openSaffronSundial() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        (new CWE22_P06_V2_SaffronSundialSafeSink()).readSaffronSundial(data);
    }
}

class CWE22_P06_V2_SaffronSundialSafeSink {
    public void readSaffronSundial(String data) {
        String saffronSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronSundialFile = new File(saffronSundialRoot + data);
            FileInputStream saffronSundialStream = null;
            InputStreamReader saffronSundialStreamReader = null;
            BufferedReader saffronSundialReader = null;
            if (saffronSundialFile.exists() && saffronSundialFile.isFile()) {
                try {
                    saffronSundialStream = new FileInputStream(saffronSundialFile);
                    saffronSundialStreamReader = new InputStreamReader(saffronSundialStream, "UTF-8");
                    saffronSundialReader = new BufferedReader(saffronSundialStreamReader);
                    System.out.println(saffronSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_SaffronSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronSundialReader != null) {
                            saffronSundialReader.close();
                        }
                        if (saffronSundialStreamReader != null) {
                            saffronSundialStreamReader.close();
                        }
                        if (saffronSundialStream != null) {
                            saffronSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_SaffronSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
