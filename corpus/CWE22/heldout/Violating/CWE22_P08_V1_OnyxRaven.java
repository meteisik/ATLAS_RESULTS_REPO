import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_OnyxRaven {

    public void openOnyxRaven() {
        String data;
        data = System.getenv("ONYX_RAVEN_PATH");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_OnyxRavenSink()).readOnyxRaven(dataArray);
    }
}

class CWE22_P08_V1_OnyxRavenSink {
    public void readOnyxRaven(String[] dataArray) {
        String data = dataArray[2];
        String onyxRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxRavenFile = new File(onyxRavenRoot + data);
            FileInputStream onyxRavenStream = null;
            InputStreamReader onyxRavenStreamReader = null;
            BufferedReader onyxRavenReader = null;
            if (onyxRavenFile.exists() && onyxRavenFile.isFile()) {
                try {
                    onyxRavenStream = new FileInputStream(onyxRavenFile);
                    onyxRavenStreamReader = new InputStreamReader(onyxRavenStream, "UTF-8");
                    onyxRavenReader = new BufferedReader(onyxRavenStreamReader);
                    System.out.println(onyxRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_OnyxRavenSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxRavenReader != null) {
                            onyxRavenReader.close();
                        }
                        if (onyxRavenStreamReader != null) {
                            onyxRavenStreamReader.close();
                        }
                        if (onyxRavenStream != null) {
                            onyxRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_OnyxRavenSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
