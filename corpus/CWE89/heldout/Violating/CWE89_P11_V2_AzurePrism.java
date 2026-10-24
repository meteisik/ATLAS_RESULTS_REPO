import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AzurePrism {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzurePrism() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_PRISM_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AzurePrismSink()).queryAzurePrism(dataHashMap);
    }
}

class CWE89_P11_V2_AzurePrismSink {
    public void queryAzurePrism(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection azurePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azurePrism");
        Statement azurePrismStatement = null;
        ResultSet azurePrismRows = null;
        try {
            azurePrismStatement = azurePrismConnection.createStatement();
            azurePrismRows = azurePrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azurePrismRows.getRow());
        } finally {
            if (azurePrismRows != null) {
                azurePrismRows.close();
            }
            if (azurePrismStatement != null) {
                azurePrismStatement.close();
            }
            azurePrismConnection.close();
        }
    }
}
