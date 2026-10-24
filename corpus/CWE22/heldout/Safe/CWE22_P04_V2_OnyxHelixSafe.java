import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V2_OnyxHelixSafe {

    private String locateOnyxHelix() {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void openOnyxHelix() {
        String data = locateOnyxHelix();
        String onyxHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxHelixFile = new File(onyxHelixRoot + data);
            FileInputStream onyxHelixStream = null;
            InputStreamReader onyxHelixStreamReader = null;
            BufferedReader onyxHelixReader = null;
            if (onyxHelixFile.exists() && onyxHelixFile.isFile()) {
                try {
                    onyxHelixStream = new FileInputStream(onyxHelixFile);
                    onyxHelixStreamReader = new InputStreamReader(onyxHelixStream, "UTF-8");
                    onyxHelixReader = new BufferedReader(onyxHelixStreamReader);
                    System.out.println(onyxHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V2_OnyxHelixSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxHelixReader != null) {
                            onyxHelixReader.close();
                        }
                        if (onyxHelixStreamReader != null) {
                            onyxHelixStreamReader.close();
                        }
                        if (onyxHelixStream != null) {
                            onyxHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V2_OnyxHelixSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
