import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_NovaMantisSafe {

    public void openNovaMantis() {
        String data;
        data = "foo";
        (new CWE22_P06_V1_NovaMantisSafeSink()).readNovaMantis(data);
    }
}

class CWE22_P06_V1_NovaMantisSafeSink {
    public void readNovaMantis(String data) {
        String novaMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File novaMantisFile = new File(novaMantisRoot + data);
            FileInputStream novaMantisStream = null;
            InputStreamReader novaMantisStreamReader = null;
            BufferedReader novaMantisReader = null;
            if (novaMantisFile.exists() && novaMantisFile.isFile()) {
                try {
                    novaMantisStream = new FileInputStream(novaMantisFile);
                    novaMantisStreamReader = new InputStreamReader(novaMantisStream, "UTF-8");
                    novaMantisReader = new BufferedReader(novaMantisStreamReader);
                    System.out.println(novaMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V1_NovaMantisSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (novaMantisReader != null) {
                            novaMantisReader.close();
                        }
                        if (novaMantisStreamReader != null) {
                            novaMantisStreamReader.close();
                        }
                        if (novaMantisStream != null) {
                            novaMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V1_NovaMantisSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
