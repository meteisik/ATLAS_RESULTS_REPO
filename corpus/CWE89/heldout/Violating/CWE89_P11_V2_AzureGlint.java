import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AzureGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureGlint() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("AZURE_GLINT_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AzureGlintSink()).queryAzureGlint(dataHashMap);
    }
}

class CWE89_P11_V2_AzureGlintSink {
    public void queryAzureGlint(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection azureGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureGlint");
        Statement azureGlintStatement = null;
        ResultSet azureGlintRows = null;
        try {
            azureGlintStatement = azureGlintConnection.createStatement();
            azureGlintRows = azureGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureGlintRows.getRow());
        } finally {
            if (azureGlintRows != null) {
                azureGlintRows.close();
            }
            if (azureGlintStatement != null) {
                azureGlintStatement.close();
            }
            azureGlintConnection.close();
        }
    }
}
