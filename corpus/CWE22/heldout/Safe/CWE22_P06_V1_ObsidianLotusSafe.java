import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_ObsidianLotusSafe {

    public void openObsidianLotus() {
        String data;
        data = "foo";
        (new CWE22_P06_V1_ObsidianLotusSafeSink()).readObsidianLotus(data);
    }
}

class CWE22_P06_V1_ObsidianLotusSafeSink {
    public void readObsidianLotus(String data) {
        String obsidianLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianLotusFile = new File(obsidianLotusRoot + data);
            FileInputStream obsidianLotusStream = null;
            InputStreamReader obsidianLotusStreamReader = null;
            BufferedReader obsidianLotusReader = null;
            if (obsidianLotusFile.exists() && obsidianLotusFile.isFile()) {
                try {
                    obsidianLotusStream = new FileInputStream(obsidianLotusFile);
                    obsidianLotusStreamReader = new InputStreamReader(obsidianLotusStream, "UTF-8");
                    obsidianLotusReader = new BufferedReader(obsidianLotusStreamReader);
                    System.out.println(obsidianLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V1_ObsidianLotusSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianLotusReader != null) {
                            obsidianLotusReader.close();
                        }
                        if (obsidianLotusStreamReader != null) {
                            obsidianLotusStreamReader.close();
                        }
                        if (obsidianLotusStream != null) {
                            obsidianLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V1_ObsidianLotusSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
