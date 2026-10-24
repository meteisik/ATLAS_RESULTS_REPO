import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AzureSignalSafe {

    public void runAzureSignal() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AzureSignalSafeSink()).queryAzureSignal(dataHashMap);
    }
}

class CWE89_P11_V2_AzureSignalSafeSink {
    public void queryAzureSignal(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection azureSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSignal");
        Statement azureSignalStatement = null;
        ResultSet azureSignalRows = null;
        try {
            azureSignalStatement = azureSignalConnection.createStatement();
            azureSignalRows = azureSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureSignalRows.getRow());
        } finally {
            if (azureSignalRows != null) {
                azureSignalRows.close();
            }
            if (azureSignalStatement != null) {
                azureSignalStatement.close();
            }
            azureSignalConnection.close();
        }
    }
}
