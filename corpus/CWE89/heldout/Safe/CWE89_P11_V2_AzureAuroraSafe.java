import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AzureAuroraSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runAzureAurora() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AzureAuroraSafeSink()).queryAzureAurora(dataHashMap);
    }
}

class CWE89_P11_V2_AzureAuroraSafeSink {
    public void queryAzureAurora(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection azureAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureAurora");
        Statement azureAuroraStatement = null;
        ResultSet azureAuroraRows = null;
        try {
            azureAuroraStatement = azureAuroraConnection.createStatement();
            azureAuroraRows = azureAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureAuroraRows.getRow());
        } finally {
            if (azureAuroraRows != null) {
                azureAuroraRows.close();
            }
            if (azureAuroraStatement != null) {
                azureAuroraStatement.close();
            }
            azureAuroraConnection.close();
        }
    }
}
