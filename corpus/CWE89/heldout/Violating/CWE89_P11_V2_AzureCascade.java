import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AzureCascade {
    private static int privateFive = 5;

    public void runAzureCascade() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("AZURE_CASCADE_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AzureCascadeSink()).queryAzureCascade(dataHashMap);
    }
}

class CWE89_P11_V2_AzureCascadeSink {
    public void queryAzureCascade(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection azureCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCascade");
        Statement azureCascadeStatement = null;
        ResultSet azureCascadeRows = null;
        try {
            azureCascadeStatement = azureCascadeConnection.createStatement();
            azureCascadeRows = azureCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureCascadeRows.getRow());
        } finally {
            if (azureCascadeRows != null) {
                azureCascadeRows.close();
            }
            if (azureCascadeStatement != null) {
                azureCascadeStatement.close();
            }
            azureCascadeConnection.close();
        }
    }
}
