import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AzureSundialSafe {

    public void runAzureSundial() throws SQLException {
        String data;
        while (true) {
            data = "foo";
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AzureSundialSafeSink()).queryAzureSundial(dataHashMap);
    }
}

class CWE89_P11_V2_AzureSundialSafeSink {
    public void queryAzureSundial(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection azureSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSundial");
        Statement azureSundialStatement = null;
        ResultSet azureSundialRows = null;
        try {
            azureSundialStatement = azureSundialConnection.createStatement();
            azureSundialRows = azureSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureSundialRows.getRow());
        } finally {
            if (azureSundialRows != null) {
                azureSundialRows.close();
            }
            if (azureSundialStatement != null) {
                azureSundialStatement.close();
            }
            azureSundialConnection.close();
        }
    }
}
