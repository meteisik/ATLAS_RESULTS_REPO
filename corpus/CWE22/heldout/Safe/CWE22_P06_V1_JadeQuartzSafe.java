import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_JadeQuartzSafe {

    public void openJadeQuartz() {
        String data;
        data = "foo";
        (new CWE22_P06_V1_JadeQuartzSafeSink()).readJadeQuartz(data);
    }
}

class CWE22_P06_V1_JadeQuartzSafeSink {
    public void readJadeQuartz(String data) {
        String jadeQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeQuartzFile = new File(jadeQuartzRoot + data);
            FileInputStream jadeQuartzStream = null;
            InputStreamReader jadeQuartzStreamReader = null;
            BufferedReader jadeQuartzReader = null;
            if (jadeQuartzFile.exists() && jadeQuartzFile.isFile()) {
                try {
                    jadeQuartzStream = new FileInputStream(jadeQuartzFile);
                    jadeQuartzStreamReader = new InputStreamReader(jadeQuartzStream, "UTF-8");
                    jadeQuartzReader = new BufferedReader(jadeQuartzStreamReader);
                    System.out.println(jadeQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V1_JadeQuartzSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeQuartzReader != null) {
                            jadeQuartzReader.close();
                        }
                        if (jadeQuartzStreamReader != null) {
                            jadeQuartzStreamReader.close();
                        }
                        if (jadeQuartzStream != null) {
                            jadeQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V1_JadeQuartzSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
