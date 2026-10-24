import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AzureQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureQuartz() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AzureQuartzSafeSink()).queryAzureQuartz(dataHashMap);
    }
}

class CWE89_P11_V2_AzureQuartzSafeSink {
    public void queryAzureQuartz(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection azureQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureQuartz");
        Statement azureQuartzStatement = null;
        ResultSet azureQuartzRows = null;
        try {
            azureQuartzStatement = azureQuartzConnection.createStatement();
            azureQuartzRows = azureQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureQuartzRows.getRow());
        } finally {
            if (azureQuartzRows != null) {
                azureQuartzRows.close();
            }
            if (azureQuartzStatement != null) {
                azureQuartzStatement.close();
            }
            azureQuartzConnection.close();
        }
    }
}
