import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AzureFlare {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureFlare() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("AZURE_FLARE_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AzureFlareSink()).queryAzureFlare(dataHashMap);
    }
}

class CWE89_P11_V2_AzureFlareSink {
    public void queryAzureFlare(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection azureFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureFlare");
        Statement azureFlareStatement = null;
        ResultSet azureFlareRows = null;
        try {
            azureFlareStatement = azureFlareConnection.createStatement();
            azureFlareRows = azureFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureFlareRows.getRow());
        } finally {
            if (azureFlareRows != null) {
                azureFlareRows.close();
            }
            if (azureFlareStatement != null) {
                azureFlareStatement.close();
            }
            azureFlareConnection.close();
        }
    }
}
