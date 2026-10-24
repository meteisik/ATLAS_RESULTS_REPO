import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_SaffronMantisSafe {

    public void openSaffronMantis() {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_SaffronMantisSafeSink()).readSaffronMantis(dataArray);
    }
}

class CWE22_P08_V1_SaffronMantisSafeSink {
    public void readSaffronMantis(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V1_SaffronMantisSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V1_SaffronMantisSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
