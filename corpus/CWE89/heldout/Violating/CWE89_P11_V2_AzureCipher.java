import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AzureCipher {
    private static boolean privateReturnsTrue() { return true; }

    public void runAzureCipher() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_CIPHER_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AzureCipherSink()).queryAzureCipher(dataHashMap);
    }
}

class CWE89_P11_V2_AzureCipherSink {
    public void queryAzureCipher(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection azureCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCipher");
        Statement azureCipherStatement = null;
        ResultSet azureCipherRows = null;
        try {
            azureCipherStatement = azureCipherConnection.createStatement();
            azureCipherRows = azureCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureCipherRows.getRow());
        } finally {
            if (azureCipherRows != null) {
                azureCipherRows.close();
            }
            if (azureCipherStatement != null) {
                azureCipherStatement.close();
            }
            azureCipherConnection.close();
        }
    }
}
